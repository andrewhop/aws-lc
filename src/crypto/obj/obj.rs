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
    pub type lhash_st_ASN1_OBJECT;
    pub type lhash_st;
    fn abort() -> !;
    fn bsearch(
        __key: *const libc::c_void,
        __base: *const libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    ) -> *mut libc::c_void;
    fn ASN1_OBJECT_create(
        nid: libc::c_int,
        data: *const uint8_t,
        len: size_t,
        sn: *const libc::c_char,
        ln: *const libc::c_char,
    ) -> *mut ASN1_OBJECT;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_OBJECT_new() -> *mut ASN1_OBJECT;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_asn1_oid_to_text(cbs: *const CBS) -> *mut libc::c_char;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_asn1_oid_from_text(
        cbb: *mut CBB,
        text: *const libc::c_char,
        len: size_t,
    ) -> libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_hash32(ptr: *const libc::c_void, len: size_t) -> uint32_t;
    fn OPENSSL_strhash(s: *const libc::c_char) -> uint32_t;
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
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
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed_0 = 0;
pub type lhash_cmp_func = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type lhash_ASN1_OBJECT_cmp_func = Option::<
    unsafe extern "C" fn(*const ASN1_OBJECT, *const ASN1_OBJECT) -> libc::c_int,
>;
pub type lhash_hash_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> uint32_t,
>;
pub type lhash_ASN1_OBJECT_hash_func = Option::<
    unsafe extern "C" fn(*const ASN1_OBJECT) -> uint32_t,
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
pub type C2RustUnnamed_0 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_0 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_0 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_0 = 0;
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
static mut kObjectData: [uint8_t; 6369] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x97 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8b as libc::c_int as uint8_t,
    0x3a as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x58 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x27 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x28 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2d as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x33 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2d as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x41 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x22 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x27 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x28 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2d as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x33 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x39 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3a as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3b as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3e as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3f as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x40 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x41 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x43 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x45 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x46 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x47 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x49 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4a as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4c as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4d as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4e as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4f as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x50 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x51 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x52 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x22 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0xae as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x22 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x27 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2d as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x28 as libc::c_int as uint8_t,
    0xcf as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x62 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x22 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x27 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x28 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x33 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3e as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x3f as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x3f as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x6e as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x70 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x71 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x6f as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x33 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
];
static mut kObjects: [ASN1_OBJECT; 999] = [asn1_object_st {
    sn: 0 as *const libc::c_char,
    ln: 0 as *const libc::c_char,
    nid: 0,
    length: 0,
    data: 0 as *const libc::c_uchar,
    flags: 0,
}; 999];
static mut kNIDsInShortNameOrder: [uint16_t; 987] = [
    364 as libc::c_int as uint16_t,
    419 as libc::c_int as uint16_t,
    916 as libc::c_int as uint16_t,
    963 as libc::c_int as uint16_t,
    421 as libc::c_int as uint16_t,
    650 as libc::c_int as uint16_t,
    653 as libc::c_int as uint16_t,
    904 as libc::c_int as uint16_t,
    418 as libc::c_int as uint16_t,
    420 as libc::c_int as uint16_t,
    913 as libc::c_int as uint16_t,
    423 as libc::c_int as uint16_t,
    917 as libc::c_int as uint16_t,
    425 as libc::c_int as uint16_t,
    651 as libc::c_int as uint16_t,
    654 as libc::c_int as uint16_t,
    905 as libc::c_int as uint16_t,
    422 as libc::c_int as uint16_t,
    424 as libc::c_int as uint16_t,
    427 as libc::c_int as uint16_t,
    918 as libc::c_int as uint16_t,
    964 as libc::c_int as uint16_t,
    429 as libc::c_int as uint16_t,
    652 as libc::c_int as uint16_t,
    655 as libc::c_int as uint16_t,
    906 as libc::c_int as uint16_t,
    426 as libc::c_int as uint16_t,
    428 as libc::c_int as uint16_t,
    914 as libc::c_int as uint16_t,
    958 as libc::c_int as uint16_t,
    955 as libc::c_int as uint16_t,
    956 as libc::c_int as uint16_t,
    954 as libc::c_int as uint16_t,
    91 as libc::c_int as uint16_t,
    93 as libc::c_int as uint16_t,
    92 as libc::c_int as uint16_t,
    94 as libc::c_int as uint16_t,
    14 as libc::c_int as uint16_t,
    751 as libc::c_int as uint16_t,
    757 as libc::c_int as uint16_t,
    760 as libc::c_int as uint16_t,
    763 as libc::c_int as uint16_t,
    754 as libc::c_int as uint16_t,
    766 as libc::c_int as uint16_t,
    752 as libc::c_int as uint16_t,
    758 as libc::c_int as uint16_t,
    761 as libc::c_int as uint16_t,
    764 as libc::c_int as uint16_t,
    755 as libc::c_int as uint16_t,
    767 as libc::c_int as uint16_t,
    753 as libc::c_int as uint16_t,
    759 as libc::c_int as uint16_t,
    762 as libc::c_int as uint16_t,
    765 as libc::c_int as uint16_t,
    756 as libc::c_int as uint16_t,
    768 as libc::c_int as uint16_t,
    108 as libc::c_int as uint16_t,
    110 as libc::c_int as uint16_t,
    109 as libc::c_int as uint16_t,
    111 as libc::c_int as uint16_t,
    894 as libc::c_int as uint16_t,
    13 as libc::c_int as uint16_t,
    141 as libc::c_int as uint16_t,
    417 as libc::c_int as uint16_t,
    950 as libc::c_int as uint16_t,
    367 as libc::c_int as uint16_t,
    391 as libc::c_int as uint16_t,
    31 as libc::c_int as uint16_t,
    643 as libc::c_int as uint16_t,
    30 as libc::c_int as uint16_t,
    656 as libc::c_int as uint16_t,
    657 as libc::c_int as uint16_t,
    29 as libc::c_int as uint16_t,
    32 as libc::c_int as uint16_t,
    43 as libc::c_int as uint16_t,
    60 as libc::c_int as uint16_t,
    62 as libc::c_int as uint16_t,
    33 as libc::c_int as uint16_t,
    44 as libc::c_int as uint16_t,
    61 as libc::c_int as uint16_t,
    658 as libc::c_int as uint16_t,
    659 as libc::c_int as uint16_t,
    63 as libc::c_int as uint16_t,
    45 as libc::c_int as uint16_t,
    80 as libc::c_int as uint16_t,
    975 as libc::c_int as uint16_t,
    380 as libc::c_int as uint16_t,
    116 as libc::c_int as uint16_t,
    66 as libc::c_int as uint16_t,
    113 as libc::c_int as uint16_t,
    70 as libc::c_int as uint16_t,
    67 as libc::c_int as uint16_t,
    297 as libc::c_int as uint16_t,
    949 as libc::c_int as uint16_t,
    997 as libc::c_int as uint16_t,
    960 as libc::c_int as uint16_t,
    99 as libc::c_int as uint16_t,
    969 as libc::c_int as uint16_t,
    855 as libc::c_int as uint16_t,
    780 as libc::c_int as uint16_t,
    781 as libc::c_int as uint16_t,
    381 as libc::c_int as uint16_t,
    34 as libc::c_int as uint16_t,
    35 as libc::c_int as uint16_t,
    36 as libc::c_int as uint16_t,
    46 as libc::c_int as uint16_t,
    181 as libc::c_int as uint16_t,
    183 as libc::c_int as uint16_t,
    645 as libc::c_int as uint16_t,
    646 as libc::c_int as uint16_t,
    970 as libc::c_int as uint16_t,
    773 as libc::c_int as uint16_t,
    974 as libc::c_int as uint16_t,
    971 as libc::c_int as uint16_t,
    972 as libc::c_int as uint16_t,
    973 as libc::c_int as uint16_t,
    957 as libc::c_int as uint16_t,
    952 as libc::c_int as uint16_t,
    953 as libc::c_int as uint16_t,
    951 as libc::c_int as uint16_t,
    15 as libc::c_int as uint16_t,
    856 as libc::c_int as uint16_t,
    3 as libc::c_int as uint16_t,
    257 as libc::c_int as uint16_t,
    4 as libc::c_int as uint16_t,
    114 as libc::c_int as uint16_t,
    95 as libc::c_int as uint16_t,
    911 as libc::c_int as uint16_t,
    994 as libc::c_int as uint16_t,
    995 as libc::c_int as uint16_t,
    996 as libc::c_int as uint16_t,
    990 as libc::c_int as uint16_t,
    987 as libc::c_int as uint16_t,
    988 as libc::c_int as uint16_t,
    985 as libc::c_int as uint16_t,
    989 as libc::c_int as uint16_t,
    986 as libc::c_int as uint16_t,
    388 as libc::c_int as uint16_t,
    57 as libc::c_int as uint16_t,
    366 as libc::c_int as uint16_t,
    17 as libc::c_int as uint16_t,
    178 as libc::c_int as uint16_t,
    180 as libc::c_int as uint16_t,
    379 as libc::c_int as uint16_t,
    18 as libc::c_int as uint16_t,
    749 as libc::c_int as uint16_t,
    750 as libc::c_int as uint16_t,
    9 as libc::c_int as uint16_t,
    168 as libc::c_int as uint16_t,
    10 as libc::c_int as uint16_t,
    169 as libc::c_int as uint16_t,
    147 as libc::c_int as uint16_t,
    146 as libc::c_int as uint16_t,
    170 as libc::c_int as uint16_t,
    148 as libc::c_int as uint16_t,
    149 as libc::c_int as uint16_t,
    68 as libc::c_int as uint16_t,
    144 as libc::c_int as uint16_t,
    145 as libc::c_int as uint16_t,
    161 as libc::c_int as uint16_t,
    69 as libc::c_int as uint16_t,
    162 as libc::c_int as uint16_t,
    127 as libc::c_int as uint16_t,
    993 as libc::c_int as uint16_t,
    935 as libc::c_int as uint16_t,
    98 as libc::c_int as uint16_t,
    166 as libc::c_int as uint16_t,
    37 as libc::c_int as uint16_t,
    39 as libc::c_int as uint16_t,
    38 as libc::c_int as uint16_t,
    40 as libc::c_int as uint16_t,
    5 as libc::c_int as uint16_t,
    97 as libc::c_int as uint16_t,
    915 as libc::c_int as uint16_t,
    120 as libc::c_int as uint16_t,
    122 as libc::c_int as uint16_t,
    121 as libc::c_int as uint16_t,
    123 as libc::c_int as uint16_t,
    117 as libc::c_int as uint16_t,
    19 as libc::c_int as uint16_t,
    7 as libc::c_int as uint16_t,
    396 as libc::c_int as uint16_t,
    8 as libc::c_int as uint16_t,
    96 as libc::c_int as uint16_t,
    104 as libc::c_int as uint16_t,
    119 as libc::c_int as uint16_t,
    42 as libc::c_int as uint16_t,
    65 as libc::c_int as uint16_t,
    115 as libc::c_int as uint16_t,
    671 as libc::c_int as uint16_t,
    668 as libc::c_int as uint16_t,
    669 as libc::c_int as uint16_t,
    670 as libc::c_int as uint16_t,
    919 as libc::c_int as uint16_t,
    912 as libc::c_int as uint16_t,
    777 as libc::c_int as uint16_t,
    779 as libc::c_int as uint16_t,
    776 as libc::c_int as uint16_t,
    778 as libc::c_int as uint16_t,
    41 as libc::c_int as uint16_t,
    64 as libc::c_int as uint16_t,
    675 as libc::c_int as uint16_t,
    672 as libc::c_int as uint16_t,
    965 as libc::c_int as uint16_t,
    966 as libc::c_int as uint16_t,
    967 as libc::c_int as uint16_t,
    968 as libc::c_int as uint16_t,
    673 as libc::c_int as uint16_t,
    674 as libc::c_int as uint16_t,
    978 as libc::c_int as uint16_t,
    962 as libc::c_int as uint16_t,
    979 as libc::c_int as uint16_t,
    980 as libc::c_int as uint16_t,
    188 as libc::c_int as uint16_t,
    167 as libc::c_int as uint16_t,
    100 as libc::c_int as uint16_t,
    16 as libc::c_int as uint16_t,
    143 as libc::c_int as uint16_t,
    981 as libc::c_int as uint16_t,
    992 as libc::c_int as uint16_t,
    998 as libc::c_int as uint16_t,
    458 as libc::c_int as uint16_t,
    948 as libc::c_int as uint16_t,
    982 as libc::c_int as uint16_t,
    991 as libc::c_int as uint16_t,
    961 as libc::c_int as uint16_t,
    11 as libc::c_int as uint16_t,
    378 as libc::c_int as uint16_t,
    12 as libc::c_int as uint16_t,
    184 as libc::c_int as uint16_t,
    185 as libc::c_int as uint16_t,
    125 as libc::c_int as uint16_t,
    478 as libc::c_int as uint16_t,
    289 as libc::c_int as uint16_t,
    287 as libc::c_int as uint16_t,
    397 as libc::c_int as uint16_t,
    288 as libc::c_int as uint16_t,
    368 as libc::c_int as uint16_t,
    446 as libc::c_int as uint16_t,
    363 as libc::c_int as uint16_t,
    376 as libc::c_int as uint16_t,
    405 as libc::c_int as uint16_t,
    910 as libc::c_int as uint16_t,
    746 as libc::c_int as uint16_t,
    370 as libc::c_int as uint16_t,
    484 as libc::c_int as uint16_t,
    485 as libc::c_int as uint16_t,
    501 as libc::c_int as uint16_t,
    177 as libc::c_int as uint16_t,
    90 as libc::c_int as uint16_t,
    882 as libc::c_int as uint16_t,
    87 as libc::c_int as uint16_t,
    365 as libc::c_int as uint16_t,
    285 as libc::c_int as uint16_t,
    921 as libc::c_int as uint16_t,
    922 as libc::c_int as uint16_t,
    923 as libc::c_int as uint16_t,
    924 as libc::c_int as uint16_t,
    925 as libc::c_int as uint16_t,
    926 as libc::c_int as uint16_t,
    927 as libc::c_int as uint16_t,
    928 as libc::c_int as uint16_t,
    929 as libc::c_int as uint16_t,
    930 as libc::c_int as uint16_t,
    931 as libc::c_int as uint16_t,
    932 as libc::c_int as uint16_t,
    933 as libc::c_int as uint16_t,
    934 as libc::c_int as uint16_t,
    494 as libc::c_int as uint16_t,
    860 as libc::c_int as uint16_t,
    691 as libc::c_int as uint16_t,
    692 as libc::c_int as uint16_t,
    697 as libc::c_int as uint16_t,
    698 as libc::c_int as uint16_t,
    684 as libc::c_int as uint16_t,
    685 as libc::c_int as uint16_t,
    686 as libc::c_int as uint16_t,
    687 as libc::c_int as uint16_t,
    693 as libc::c_int as uint16_t,
    699 as libc::c_int as uint16_t,
    700 as libc::c_int as uint16_t,
    702 as libc::c_int as uint16_t,
    688 as libc::c_int as uint16_t,
    689 as libc::c_int as uint16_t,
    690 as libc::c_int as uint16_t,
    694 as libc::c_int as uint16_t,
    695 as libc::c_int as uint16_t,
    696 as libc::c_int as uint16_t,
    701 as libc::c_int as uint16_t,
    703 as libc::c_int as uint16_t,
    881 as libc::c_int as uint16_t,
    483 as libc::c_int as uint16_t,
    179 as libc::c_int as uint16_t,
    785 as libc::c_int as uint16_t,
    443 as libc::c_int as uint16_t,
    152 as libc::c_int as uint16_t,
    677 as libc::c_int as uint16_t,
    771 as libc::c_int as uint16_t,
    89 as libc::c_int as uint16_t,
    883 as libc::c_int as uint16_t,
    54 as libc::c_int as uint16_t,
    407 as libc::c_int as uint16_t,
    395 as libc::c_int as uint16_t,
    130 as libc::c_int as uint16_t,
    131 as libc::c_int as uint16_t,
    50 as libc::c_int as uint16_t,
    53 as libc::c_int as uint16_t,
    153 as libc::c_int as uint16_t,
    103 as libc::c_int as uint16_t,
    88 as libc::c_int as uint16_t,
    884 as libc::c_int as uint16_t,
    806 as libc::c_int as uint16_t,
    805 as libc::c_int as uint16_t,
    500 as libc::c_int as uint16_t,
    451 as libc::c_int as uint16_t,
    495 as libc::c_int as uint16_t,
    434 as libc::c_int as uint16_t,
    390 as libc::c_int as uint16_t,
    140 as libc::c_int as uint16_t,
    891 as libc::c_int as uint16_t,
    107 as libc::c_int as uint16_t,
    871 as libc::c_int as uint16_t,
    947 as libc::c_int as uint16_t,
    946 as libc::c_int as uint16_t,
    28 as libc::c_int as uint16_t,
    941 as libc::c_int as uint16_t,
    942 as libc::c_int as uint16_t,
    943 as libc::c_int as uint16_t,
    944 as libc::c_int as uint16_t,
    945 as libc::c_int as uint16_t,
    936 as libc::c_int as uint16_t,
    937 as libc::c_int as uint16_t,
    938 as libc::c_int as uint16_t,
    939 as libc::c_int as uint16_t,
    940 as libc::c_int as uint16_t,
    920 as libc::c_int as uint16_t,
    382 as libc::c_int as uint16_t,
    887 as libc::c_int as uint16_t,
    892 as libc::c_int as uint16_t,
    174 as libc::c_int as uint16_t,
    447 as libc::c_int as uint16_t,
    471 as libc::c_int as uint16_t,
    468 as libc::c_int as uint16_t,
    472 as libc::c_int as uint16_t,
    502 as libc::c_int as uint16_t,
    449 as libc::c_int as uint16_t,
    469 as libc::c_int as uint16_t,
    470 as libc::c_int as uint16_t,
    392 as libc::c_int as uint16_t,
    452 as libc::c_int as uint16_t,
    802 as libc::c_int as uint16_t,
    803 as libc::c_int as uint16_t,
    791 as libc::c_int as uint16_t,
    416 as libc::c_int as uint16_t,
    793 as libc::c_int as uint16_t,
    794 as libc::c_int as uint16_t,
    795 as libc::c_int as uint16_t,
    796 as libc::c_int as uint16_t,
    792 as libc::c_int as uint16_t,
    48 as libc::c_int as uint16_t,
    132 as libc::c_int as uint16_t,
    885 as libc::c_int as uint16_t,
    389 as libc::c_int as uint16_t,
    384 as libc::c_int as uint16_t,
    172 as libc::c_int as uint16_t,
    56 as libc::c_int as uint16_t,
    126 as libc::c_int as uint16_t,
    372 as libc::c_int as uint16_t,
    867 as libc::c_int as uint16_t,
    462 as libc::c_int as uint16_t,
    976 as libc::c_int as uint16_t,
    983 as libc::c_int as uint16_t,
    977 as libc::c_int as uint16_t,
    984 as libc::c_int as uint16_t,
    857 as libc::c_int as uint16_t,
    453 as libc::c_int as uint16_t,
    490 as libc::c_int as uint16_t,
    156 as libc::c_int as uint16_t,
    509 as libc::c_int as uint16_t,
    815 as libc::c_int as uint16_t,
    811 as libc::c_int as uint16_t,
    851 as libc::c_int as uint16_t,
    813 as libc::c_int as uint16_t,
    814 as libc::c_int as uint16_t,
    812 as libc::c_int as uint16_t,
    850 as libc::c_int as uint16_t,
    797 as libc::c_int as uint16_t,
    163 as libc::c_int as uint16_t,
    798 as libc::c_int as uint16_t,
    799 as libc::c_int as uint16_t,
    800 as libc::c_int as uint16_t,
    801 as libc::c_int as uint16_t,
    432 as libc::c_int as uint16_t,
    430 as libc::c_int as uint16_t,
    431 as libc::c_int as uint16_t,
    433 as libc::c_int as uint16_t,
    486 as libc::c_int as uint16_t,
    473 as libc::c_int as uint16_t,
    466 as libc::c_int as uint16_t,
    889 as libc::c_int as uint16_t,
    442 as libc::c_int as uint16_t,
    783 as libc::c_int as uint16_t,
    824 as libc::c_int as uint16_t,
    825 as libc::c_int as uint16_t,
    826 as libc::c_int as uint16_t,
    827 as libc::c_int as uint16_t,
    819 as libc::c_int as uint16_t,
    829 as libc::c_int as uint16_t,
    828 as libc::c_int as uint16_t,
    830 as libc::c_int as uint16_t,
    820 as libc::c_int as uint16_t,
    823 as libc::c_int as uint16_t,
    849 as libc::c_int as uint16_t,
    840 as libc::c_int as uint16_t,
    841 as libc::c_int as uint16_t,
    842 as libc::c_int as uint16_t,
    843 as libc::c_int as uint16_t,
    844 as libc::c_int as uint16_t,
    854 as libc::c_int as uint16_t,
    839 as libc::c_int as uint16_t,
    817 as libc::c_int as uint16_t,
    832 as libc::c_int as uint16_t,
    833 as libc::c_int as uint16_t,
    834 as libc::c_int as uint16_t,
    835 as libc::c_int as uint16_t,
    836 as libc::c_int as uint16_t,
    837 as libc::c_int as uint16_t,
    838 as libc::c_int as uint16_t,
    831 as libc::c_int as uint16_t,
    845 as libc::c_int as uint16_t,
    846 as libc::c_int as uint16_t,
    847 as libc::c_int as uint16_t,
    848 as libc::c_int as uint16_t,
    818 as libc::c_int as uint16_t,
    822 as libc::c_int as uint16_t,
    821 as libc::c_int as uint16_t,
    807 as libc::c_int as uint16_t,
    853 as libc::c_int as uint16_t,
    808 as libc::c_int as uint16_t,
    852 as libc::c_int as uint16_t,
    810 as libc::c_int as uint16_t,
    782 as libc::c_int as uint16_t,
    266 as libc::c_int as uint16_t,
    355 as libc::c_int as uint16_t,
    354 as libc::c_int as uint16_t,
    356 as libc::c_int as uint16_t,
    399 as libc::c_int as uint16_t,
    357 as libc::c_int as uint16_t,
    358 as libc::c_int as uint16_t,
    176 as libc::c_int as uint16_t,
    896 as libc::c_int as uint16_t,
    895 as libc::c_int as uint16_t,
    788 as libc::c_int as uint16_t,
    897 as libc::c_int as uint16_t,
    899 as libc::c_int as uint16_t,
    898 as libc::c_int as uint16_t,
    789 as libc::c_int as uint16_t,
    900 as libc::c_int as uint16_t,
    902 as libc::c_int as uint16_t,
    901 as libc::c_int as uint16_t,
    790 as libc::c_int as uint16_t,
    903 as libc::c_int as uint16_t,
    262 as libc::c_int as uint16_t,
    893 as libc::c_int as uint16_t,
    323 as libc::c_int as uint16_t,
    326 as libc::c_int as uint16_t,
    325 as libc::c_int as uint16_t,
    324 as libc::c_int as uint16_t,
    907 as libc::c_int as uint16_t,
    908 as libc::c_int as uint16_t,
    909 as libc::c_int as uint16_t,
    268 as libc::c_int as uint16_t,
    361 as libc::c_int as uint16_t,
    362 as libc::c_int as uint16_t,
    360 as libc::c_int as uint16_t,
    81 as libc::c_int as uint16_t,
    680 as libc::c_int as uint16_t,
    263 as libc::c_int as uint16_t,
    334 as libc::c_int as uint16_t,
    346 as libc::c_int as uint16_t,
    330 as libc::c_int as uint16_t,
    336 as libc::c_int as uint16_t,
    335 as libc::c_int as uint16_t,
    339 as libc::c_int as uint16_t,
    338 as libc::c_int as uint16_t,
    328 as libc::c_int as uint16_t,
    329 as libc::c_int as uint16_t,
    337 as libc::c_int as uint16_t,
    344 as libc::c_int as uint16_t,
    345 as libc::c_int as uint16_t,
    343 as libc::c_int as uint16_t,
    333 as libc::c_int as uint16_t,
    341 as libc::c_int as uint16_t,
    342 as libc::c_int as uint16_t,
    340 as libc::c_int as uint16_t,
    332 as libc::c_int as uint16_t,
    327 as libc::c_int as uint16_t,
    331 as libc::c_int as uint16_t,
    787 as libc::c_int as uint16_t,
    408 as libc::c_int as uint16_t,
    508 as libc::c_int as uint16_t,
    507 as libc::c_int as uint16_t,
    260 as libc::c_int as uint16_t,
    302 as libc::c_int as uint16_t,
    298 as libc::c_int as uint16_t,
    311 as libc::c_int as uint16_t,
    303 as libc::c_int as uint16_t,
    300 as libc::c_int as uint16_t,
    310 as libc::c_int as uint16_t,
    308 as libc::c_int as uint16_t,
    307 as libc::c_int as uint16_t,
    312 as libc::c_int as uint16_t,
    301 as libc::c_int as uint16_t,
    309 as libc::c_int as uint16_t,
    299 as libc::c_int as uint16_t,
    305 as libc::c_int as uint16_t,
    306 as libc::c_int as uint16_t,
    784 as libc::c_int as uint16_t,
    304 as libc::c_int as uint16_t,
    128 as libc::c_int as uint16_t,
    280 as libc::c_int as uint16_t,
    274 as libc::c_int as uint16_t,
    277 as libc::c_int as uint16_t,
    284 as libc::c_int as uint16_t,
    273 as libc::c_int as uint16_t,
    283 as libc::c_int as uint16_t,
    275 as libc::c_int as uint16_t,
    276 as libc::c_int as uint16_t,
    282 as libc::c_int as uint16_t,
    278 as libc::c_int as uint16_t,
    279 as libc::c_int as uint16_t,
    281 as libc::c_int as uint16_t,
    264 as libc::c_int as uint16_t,
    858 as libc::c_int as uint16_t,
    347 as libc::c_int as uint16_t,
    265 as libc::c_int as uint16_t,
    352 as libc::c_int as uint16_t,
    353 as libc::c_int as uint16_t,
    348 as libc::c_int as uint16_t,
    351 as libc::c_int as uint16_t,
    349 as libc::c_int as uint16_t,
    175 as libc::c_int as uint16_t,
    261 as libc::c_int as uint16_t,
    258 as libc::c_int as uint16_t,
    269 as libc::c_int as uint16_t,
    271 as libc::c_int as uint16_t,
    270 as libc::c_int as uint16_t,
    272 as libc::c_int as uint16_t,
    662 as libc::c_int as uint16_t,
    664 as libc::c_int as uint16_t,
    667 as libc::c_int as uint16_t,
    665 as libc::c_int as uint16_t,
    267 as libc::c_int as uint16_t,
    359 as libc::c_int as uint16_t,
    259 as libc::c_int as uint16_t,
    164 as libc::c_int as uint16_t,
    165 as libc::c_int as uint16_t,
    313 as libc::c_int as uint16_t,
    316 as libc::c_int as uint16_t,
    319 as libc::c_int as uint16_t,
    318 as libc::c_int as uint16_t,
    317 as libc::c_int as uint16_t,
    320 as libc::c_int as uint16_t,
    315 as libc::c_int as uint16_t,
    314 as libc::c_int as uint16_t,
    322 as libc::c_int as uint16_t,
    321 as libc::c_int as uint16_t,
    512 as libc::c_int as uint16_t,
    191 as libc::c_int as uint16_t,
    215 as libc::c_int as uint16_t,
    218 as libc::c_int as uint16_t,
    221 as libc::c_int as uint16_t,
    240 as libc::c_int as uint16_t,
    217 as libc::c_int as uint16_t,
    222 as libc::c_int as uint16_t,
    220 as libc::c_int as uint16_t,
    232 as libc::c_int as uint16_t,
    233 as libc::c_int as uint16_t,
    238 as libc::c_int as uint16_t,
    237 as libc::c_int as uint16_t,
    234 as libc::c_int as uint16_t,
    227 as libc::c_int as uint16_t,
    231 as libc::c_int as uint16_t,
    236 as libc::c_int as uint16_t,
    230 as libc::c_int as uint16_t,
    235 as libc::c_int as uint16_t,
    226 as libc::c_int as uint16_t,
    229 as libc::c_int as uint16_t,
    228 as libc::c_int as uint16_t,
    219 as libc::c_int as uint16_t,
    214 as libc::c_int as uint16_t,
    216 as libc::c_int as uint16_t,
    212 as libc::c_int as uint16_t,
    213 as libc::c_int as uint16_t,
    239 as libc::c_int as uint16_t,
    223 as libc::c_int as uint16_t,
    224 as libc::c_int as uint16_t,
    225 as libc::c_int as uint16_t,
    192 as libc::c_int as uint16_t,
    243 as libc::c_int as uint16_t,
    246 as libc::c_int as uint16_t,
    247 as libc::c_int as uint16_t,
    245 as libc::c_int as uint16_t,
    241 as libc::c_int as uint16_t,
    242 as libc::c_int as uint16_t,
    244 as libc::c_int as uint16_t,
    193 as libc::c_int as uint16_t,
    248 as libc::c_int as uint16_t,
    190 as libc::c_int as uint16_t,
    210 as libc::c_int as uint16_t,
    211 as libc::c_int as uint16_t,
    208 as libc::c_int as uint16_t,
    207 as libc::c_int as uint16_t,
    205 as libc::c_int as uint16_t,
    786 as libc::c_int as uint16_t,
    209 as libc::c_int as uint16_t,
    206 as libc::c_int as uint16_t,
    204 as libc::c_int as uint16_t,
    195 as libc::c_int as uint16_t,
    255 as libc::c_int as uint16_t,
    256 as libc::c_int as uint16_t,
    253 as libc::c_int as uint16_t,
    251 as libc::c_int as uint16_t,
    252 as libc::c_int as uint16_t,
    254 as libc::c_int as uint16_t,
    189 as libc::c_int as uint16_t,
    196 as libc::c_int as uint16_t,
    197 as libc::c_int as uint16_t,
    202 as libc::c_int as uint16_t,
    203 as libc::c_int as uint16_t,
    200 as libc::c_int as uint16_t,
    201 as libc::c_int as uint16_t,
    199 as libc::c_int as uint16_t,
    198 as libc::c_int as uint16_t,
    194 as libc::c_int as uint16_t,
    250 as libc::c_int as uint16_t,
    249 as libc::c_int as uint16_t,
    676 as libc::c_int as uint16_t,
    461 as libc::c_int as uint16_t,
    748 as libc::c_int as uint16_t,
    101 as libc::c_int as uint16_t,
    647 as libc::c_int as uint16_t,
    869 as libc::c_int as uint16_t,
    142 as libc::c_int as uint16_t,
    294 as libc::c_int as uint16_t,
    295 as libc::c_int as uint16_t,
    296 as libc::c_int as uint16_t,
    86 as libc::c_int as uint16_t,
    770 as libc::c_int as uint16_t,
    492 as libc::c_int as uint16_t,
    150 as libc::c_int as uint16_t,
    83 as libc::c_int as uint16_t,
    477 as libc::c_int as uint16_t,
    476 as libc::c_int as uint16_t,
    157 as libc::c_int as uint16_t,
    480 as libc::c_int as uint16_t,
    460 as libc::c_int as uint16_t,
    493 as libc::c_int as uint16_t,
    467 as libc::c_int as uint16_t,
    809 as libc::c_int as uint16_t,
    875 as libc::c_int as uint16_t,
    182 as libc::c_int as uint16_t,
    51 as libc::c_int as uint16_t,
    383 as libc::c_int as uint16_t,
    504 as libc::c_int as uint16_t,
    506 as libc::c_int as uint16_t,
    505 as libc::c_int as uint16_t,
    488 as libc::c_int as uint16_t,
    136 as libc::c_int as uint16_t,
    135 as libc::c_int as uint16_t,
    134 as libc::c_int as uint16_t,
    138 as libc::c_int as uint16_t,
    171 as libc::c_int as uint16_t,
    137 as libc::c_int as uint16_t,
    648 as libc::c_int as uint16_t,
    649 as libc::c_int as uint16_t,
    481 as libc::c_int as uint16_t,
    173 as libc::c_int as uint16_t,
    666 as libc::c_int as uint16_t,
    369 as libc::c_int as uint16_t,
    403 as libc::c_int as uint16_t,
    72 as libc::c_int as uint16_t,
    76 as libc::c_int as uint16_t,
    74 as libc::c_int as uint16_t,
    58 as libc::c_int as uint16_t,
    79 as libc::c_int as uint16_t,
    71 as libc::c_int as uint16_t,
    78 as libc::c_int as uint16_t,
    59 as libc::c_int as uint16_t,
    75 as libc::c_int as uint16_t,
    73 as libc::c_int as uint16_t,
    139 as libc::c_int as uint16_t,
    77 as libc::c_int as uint16_t,
    681 as libc::c_int as uint16_t,
    491 as libc::c_int as uint16_t,
    475 as libc::c_int as uint16_t,
    876 as libc::c_int as uint16_t,
    489 as libc::c_int as uint16_t,
    374 as libc::c_int as uint16_t,
    112 as libc::c_int as uint16_t,
    499 as libc::c_int as uint16_t,
    487 as libc::c_int as uint16_t,
    464 as libc::c_int as uint16_t,
    863 as libc::c_int as uint16_t,
    437 as libc::c_int as uint16_t,
    439 as libc::c_int as uint16_t,
    438 as libc::c_int as uint16_t,
    479 as libc::c_int as uint16_t,
    456 as libc::c_int as uint16_t,
    441 as libc::c_int as uint16_t,
    444 as libc::c_int as uint16_t,
    440 as libc::c_int as uint16_t,
    455 as libc::c_int as uint16_t,
    445 as libc::c_int as uint16_t,
    2 as libc::c_int as uint16_t,
    186 as libc::c_int as uint16_t,
    27 as libc::c_int as uint16_t,
    187 as libc::c_int as uint16_t,
    20 as libc::c_int as uint16_t,
    21 as libc::c_int as uint16_t,
    25 as libc::c_int as uint16_t,
    26 as libc::c_int as uint16_t,
    23 as libc::c_int as uint16_t,
    24 as libc::c_int as uint16_t,
    22 as libc::c_int as uint16_t,
    151 as libc::c_int as uint16_t,
    47 as libc::c_int as uint16_t,
    401 as libc::c_int as uint16_t,
    747 as libc::c_int as uint16_t,
    862 as libc::c_int as uint16_t,
    861 as libc::c_int as uint16_t,
    661 as libc::c_int as uint16_t,
    683 as libc::c_int as uint16_t,
    872 as libc::c_int as uint16_t,
    873 as libc::c_int as uint16_t,
    816 as libc::c_int as uint16_t,
    406 as libc::c_int as uint16_t,
    409 as libc::c_int as uint16_t,
    410 as libc::c_int as uint16_t,
    411 as libc::c_int as uint16_t,
    412 as libc::c_int as uint16_t,
    413 as libc::c_int as uint16_t,
    414 as libc::c_int as uint16_t,
    415 as libc::c_int as uint16_t,
    385 as libc::c_int as uint16_t,
    84 as libc::c_int as uint16_t,
    886 as libc::c_int as uint16_t,
    663 as libc::c_int as uint16_t,
    510 as libc::c_int as uint16_t,
    435 as libc::c_int as uint16_t,
    286 as libc::c_int as uint16_t,
    457 as libc::c_int as uint16_t,
    450 as libc::c_int as uint16_t,
    870 as libc::c_int as uint16_t,
    400 as libc::c_int as uint16_t,
    877 as libc::c_int as uint16_t,
    448 as libc::c_int as uint16_t,
    463 as libc::c_int as uint16_t,
    6 as libc::c_int as uint16_t,
    644 as libc::c_int as uint16_t,
    377 as libc::c_int as uint16_t,
    1 as libc::c_int as uint16_t,
    482 as libc::c_int as uint16_t,
    155 as libc::c_int as uint16_t,
    291 as libc::c_int as uint16_t,
    290 as libc::c_int as uint16_t,
    292 as libc::c_int as uint16_t,
    159 as libc::c_int as uint16_t,
    859 as libc::c_int as uint16_t,
    704 as libc::c_int as uint16_t,
    705 as libc::c_int as uint16_t,
    706 as libc::c_int as uint16_t,
    707 as libc::c_int as uint16_t,
    708 as libc::c_int as uint16_t,
    709 as libc::c_int as uint16_t,
    710 as libc::c_int as uint16_t,
    711 as libc::c_int as uint16_t,
    712 as libc::c_int as uint16_t,
    713 as libc::c_int as uint16_t,
    714 as libc::c_int as uint16_t,
    715 as libc::c_int as uint16_t,
    716 as libc::c_int as uint16_t,
    154 as libc::c_int as uint16_t,
    474 as libc::c_int as uint16_t,
    717 as libc::c_int as uint16_t,
    718 as libc::c_int as uint16_t,
    719 as libc::c_int as uint16_t,
    720 as libc::c_int as uint16_t,
    721 as libc::c_int as uint16_t,
    722 as libc::c_int as uint16_t,
    723 as libc::c_int as uint16_t,
    724 as libc::c_int as uint16_t,
    725 as libc::c_int as uint16_t,
    726 as libc::c_int as uint16_t,
    727 as libc::c_int as uint16_t,
    728 as libc::c_int as uint16_t,
    729 as libc::c_int as uint16_t,
    730 as libc::c_int as uint16_t,
    731 as libc::c_int as uint16_t,
    732 as libc::c_int as uint16_t,
    733 as libc::c_int as uint16_t,
    734 as libc::c_int as uint16_t,
    386 as libc::c_int as uint16_t,
    878 as libc::c_int as uint16_t,
    394 as libc::c_int as uint16_t,
    105 as libc::c_int as uint16_t,
    129 as libc::c_int as uint16_t,
    371 as libc::c_int as uint16_t,
    625 as libc::c_int as uint16_t,
    515 as libc::c_int as uint16_t,
    518 as libc::c_int as uint16_t,
    638 as libc::c_int as uint16_t,
    637 as libc::c_int as uint16_t,
    636 as libc::c_int as uint16_t,
    639 as libc::c_int as uint16_t,
    641 as libc::c_int as uint16_t,
    642 as libc::c_int as uint16_t,
    640 as libc::c_int as uint16_t,
    517 as libc::c_int as uint16_t,
    513 as libc::c_int as uint16_t,
    514 as libc::c_int as uint16_t,
    516 as libc::c_int as uint16_t,
    607 as libc::c_int as uint16_t,
    624 as libc::c_int as uint16_t,
    620 as libc::c_int as uint16_t,
    631 as libc::c_int as uint16_t,
    623 as libc::c_int as uint16_t,
    628 as libc::c_int as uint16_t,
    630 as libc::c_int as uint16_t,
    629 as libc::c_int as uint16_t,
    621 as libc::c_int as uint16_t,
    635 as libc::c_int as uint16_t,
    632 as libc::c_int as uint16_t,
    633 as libc::c_int as uint16_t,
    634 as libc::c_int as uint16_t,
    627 as libc::c_int as uint16_t,
    626 as libc::c_int as uint16_t,
    622 as libc::c_int as uint16_t,
    619 as libc::c_int as uint16_t,
    615 as libc::c_int as uint16_t,
    616 as libc::c_int as uint16_t,
    618 as libc::c_int as uint16_t,
    617 as libc::c_int as uint16_t,
    611 as libc::c_int as uint16_t,
    609 as libc::c_int as uint16_t,
    608 as libc::c_int as uint16_t,
    610 as libc::c_int as uint16_t,
    613 as libc::c_int as uint16_t,
    614 as libc::c_int as uint16_t,
    612 as libc::c_int as uint16_t,
    540 as libc::c_int as uint16_t,
    576 as libc::c_int as uint16_t,
    570 as libc::c_int as uint16_t,
    534 as libc::c_int as uint16_t,
    527 as libc::c_int as uint16_t,
    571 as libc::c_int as uint16_t,
    572 as libc::c_int as uint16_t,
    535 as libc::c_int as uint16_t,
    536 as libc::c_int as uint16_t,
    528 as libc::c_int as uint16_t,
    577 as libc::c_int as uint16_t,
    541 as libc::c_int as uint16_t,
    529 as libc::c_int as uint16_t,
    542 as libc::c_int as uint16_t,
    578 as libc::c_int as uint16_t,
    579 as libc::c_int as uint16_t,
    543 as libc::c_int as uint16_t,
    573 as libc::c_int as uint16_t,
    537 as libc::c_int as uint16_t,
    600 as libc::c_int as uint16_t,
    558 as libc::c_int as uint16_t,
    592 as libc::c_int as uint16_t,
    559 as libc::c_int as uint16_t,
    593 as libc::c_int as uint16_t,
    599 as libc::c_int as uint16_t,
    598 as libc::c_int as uint16_t,
    580 as libc::c_int as uint16_t,
    581 as libc::c_int as uint16_t,
    544 as libc::c_int as uint16_t,
    545 as libc::c_int as uint16_t,
    546 as libc::c_int as uint16_t,
    582 as libc::c_int as uint16_t,
    583 as libc::c_int as uint16_t,
    584 as libc::c_int as uint16_t,
    547 as libc::c_int as uint16_t,
    548 as libc::c_int as uint16_t,
    549 as libc::c_int as uint16_t,
    585 as libc::c_int as uint16_t,
    538 as libc::c_int as uint16_t,
    530 as libc::c_int as uint16_t,
    574 as libc::c_int as uint16_t,
    575 as libc::c_int as uint16_t,
    539 as libc::c_int as uint16_t,
    560 as libc::c_int as uint16_t,
    566 as libc::c_int as uint16_t,
    563 as libc::c_int as uint16_t,
    595 as libc::c_int as uint16_t,
    596 as libc::c_int as uint16_t,
    564 as libc::c_int as uint16_t,
    565 as libc::c_int as uint16_t,
    597 as libc::c_int as uint16_t,
    586 as libc::c_int as uint16_t,
    587 as libc::c_int as uint16_t,
    550 as libc::c_int as uint16_t,
    551 as libc::c_int as uint16_t,
    552 as libc::c_int as uint16_t,
    588 as libc::c_int as uint16_t,
    589 as libc::c_int as uint16_t,
    590 as libc::c_int as uint16_t,
    553 as libc::c_int as uint16_t,
    554 as libc::c_int as uint16_t,
    555 as libc::c_int as uint16_t,
    591 as libc::c_int as uint16_t,
    567 as libc::c_int as uint16_t,
    526 as libc::c_int as uint16_t,
    561 as libc::c_int as uint16_t,
    522 as libc::c_int as uint16_t,
    519 as libc::c_int as uint16_t,
    521 as libc::c_int as uint16_t,
    520 as libc::c_int as uint16_t,
    556 as libc::c_int as uint16_t,
    557 as libc::c_int as uint16_t,
    523 as libc::c_int as uint16_t,
    532 as libc::c_int as uint16_t,
    524 as libc::c_int as uint16_t,
    525 as libc::c_int as uint16_t,
    568 as libc::c_int as uint16_t,
    569 as libc::c_int as uint16_t,
    531 as libc::c_int as uint16_t,
    533 as libc::c_int as uint16_t,
    594 as libc::c_int as uint16_t,
    562 as libc::c_int as uint16_t,
    606 as libc::c_int as uint16_t,
    601 as libc::c_int as uint16_t,
    602 as libc::c_int as uint16_t,
    604 as libc::c_int as uint16_t,
    603 as libc::c_int as uint16_t,
    605 as libc::c_int as uint16_t,
    52 as libc::c_int as uint16_t,
    454 as libc::c_int as uint16_t,
    496 as libc::c_int as uint16_t,
    387 as libc::c_int as uint16_t,
    660 as libc::c_int as uint16_t,
    85 as libc::c_int as uint16_t,
    769 as libc::c_int as uint16_t,
    398 as libc::c_int as uint16_t,
    82 as libc::c_int as uint16_t,
    498 as libc::c_int as uint16_t,
    497 as libc::c_int as uint16_t,
    890 as libc::c_int as uint16_t,
    874 as libc::c_int as uint16_t,
    402 as libc::c_int as uint16_t,
    864 as libc::c_int as uint16_t,
    866 as libc::c_int as uint16_t,
    865 as libc::c_int as uint16_t,
    459 as libc::c_int as uint16_t,
    293 as libc::c_int as uint16_t,
    133 as libc::c_int as uint16_t,
    106 as libc::c_int as uint16_t,
    682 as libc::c_int as uint16_t,
    375 as libc::c_int as uint16_t,
    436 as libc::c_int as uint16_t,
    888 as libc::c_int as uint16_t,
    55 as libc::c_int as uint16_t,
    49 as libc::c_int as uint16_t,
    880 as libc::c_int as uint16_t,
    465 as libc::c_int as uint16_t,
    879 as libc::c_int as uint16_t,
    373 as libc::c_int as uint16_t,
    678 as libc::c_int as uint16_t,
    679 as libc::c_int as uint16_t,
    735 as libc::c_int as uint16_t,
    743 as libc::c_int as uint16_t,
    744 as libc::c_int as uint16_t,
    745 as libc::c_int as uint16_t,
    736 as libc::c_int as uint16_t,
    737 as libc::c_int as uint16_t,
    738 as libc::c_int as uint16_t,
    739 as libc::c_int as uint16_t,
    740 as libc::c_int as uint16_t,
    741 as libc::c_int as uint16_t,
    742 as libc::c_int as uint16_t,
    804 as libc::c_int as uint16_t,
    868 as libc::c_int as uint16_t,
    503 as libc::c_int as uint16_t,
    158 as libc::c_int as uint16_t,
    160 as libc::c_int as uint16_t,
];
static mut kNIDsInLongNameOrder: [uint16_t; 987] = [
    363 as libc::c_int as uint16_t,
    405 as libc::c_int as uint16_t,
    368 as libc::c_int as uint16_t,
    910 as libc::c_int as uint16_t,
    664 as libc::c_int as uint16_t,
    177 as libc::c_int as uint16_t,
    365 as libc::c_int as uint16_t,
    285 as libc::c_int as uint16_t,
    179 as libc::c_int as uint16_t,
    785 as libc::c_int as uint16_t,
    131 as libc::c_int as uint16_t,
    975 as libc::c_int as uint16_t,
    783 as libc::c_int as uint16_t,
    382 as libc::c_int as uint16_t,
    392 as libc::c_int as uint16_t,
    132 as libc::c_int as uint16_t,
    949 as libc::c_int as uint16_t,
    997 as libc::c_int as uint16_t,
    960 as libc::c_int as uint16_t,
    389 as libc::c_int as uint16_t,
    384 as libc::c_int as uint16_t,
    372 as libc::c_int as uint16_t,
    172 as libc::c_int as uint16_t,
    813 as libc::c_int as uint16_t,
    849 as libc::c_int as uint16_t,
    815 as libc::c_int as uint16_t,
    851 as libc::c_int as uint16_t,
    850 as libc::c_int as uint16_t,
    811 as libc::c_int as uint16_t,
    817 as libc::c_int as uint16_t,
    812 as libc::c_int as uint16_t,
    818 as libc::c_int as uint16_t,
    809 as libc::c_int as uint16_t,
    816 as libc::c_int as uint16_t,
    807 as libc::c_int as uint16_t,
    853 as libc::c_int as uint16_t,
    808 as libc::c_int as uint16_t,
    852 as libc::c_int as uint16_t,
    854 as libc::c_int as uint16_t,
    810 as libc::c_int as uint16_t,
    432 as libc::c_int as uint16_t,
    430 as libc::c_int as uint16_t,
    431 as libc::c_int as uint16_t,
    433 as libc::c_int as uint16_t,
    634 as libc::c_int as uint16_t,
    294 as libc::c_int as uint16_t,
    295 as libc::c_int as uint16_t,
    296 as libc::c_int as uint16_t,
    182 as libc::c_int as uint16_t,
    183 as libc::c_int as uint16_t,
    667 as libc::c_int as uint16_t,
    665 as libc::c_int as uint16_t,
    647 as libc::c_int as uint16_t,
    142 as libc::c_int as uint16_t,
    974 as libc::c_int as uint16_t,
    971 as libc::c_int as uint16_t,
    972 as libc::c_int as uint16_t,
    973 as libc::c_int as uint16_t,
    504 as libc::c_int as uint16_t,
    994 as libc::c_int as uint16_t,
    995 as libc::c_int as uint16_t,
    996 as libc::c_int as uint16_t,
    990 as libc::c_int as uint16_t,
    987 as libc::c_int as uint16_t,
    988 as libc::c_int as uint16_t,
    985 as libc::c_int as uint16_t,
    989 as libc::c_int as uint16_t,
    986 as libc::c_int as uint16_t,
    388 as libc::c_int as uint16_t,
    383 as libc::c_int as uint16_t,
    417 as libc::c_int as uint16_t,
    135 as libc::c_int as uint16_t,
    138 as libc::c_int as uint16_t,
    171 as libc::c_int as uint16_t,
    134 as libc::c_int as uint16_t,
    856 as libc::c_int as uint16_t,
    137 as libc::c_int as uint16_t,
    648 as libc::c_int as uint16_t,
    136 as libc::c_int as uint16_t,
    649 as libc::c_int as uint16_t,
    72 as libc::c_int as uint16_t,
    76 as libc::c_int as uint16_t,
    74 as libc::c_int as uint16_t,
    71 as libc::c_int as uint16_t,
    58 as libc::c_int as uint16_t,
    79 as libc::c_int as uint16_t,
    78 as libc::c_int as uint16_t,
    57 as libc::c_int as uint16_t,
    59 as libc::c_int as uint16_t,
    75 as libc::c_int as uint16_t,
    73 as libc::c_int as uint16_t,
    77 as libc::c_int as uint16_t,
    139 as libc::c_int as uint16_t,
    178 as libc::c_int as uint16_t,
    370 as libc::c_int as uint16_t,
    367 as libc::c_int as uint16_t,
    369 as libc::c_int as uint16_t,
    366 as libc::c_int as uint16_t,
    371 as libc::c_int as uint16_t,
    180 as libc::c_int as uint16_t,
    161 as libc::c_int as uint16_t,
    69 as libc::c_int as uint16_t,
    162 as libc::c_int as uint16_t,
    127 as libc::c_int as uint16_t,
    993 as libc::c_int as uint16_t,
    858 as libc::c_int as uint16_t,
    164 as libc::c_int as uint16_t,
    165 as libc::c_int as uint16_t,
    385 as libc::c_int as uint16_t,
    663 as libc::c_int as uint16_t,
    1 as libc::c_int as uint16_t,
    2 as libc::c_int as uint16_t,
    188 as libc::c_int as uint16_t,
    167 as libc::c_int as uint16_t,
    387 as libc::c_int as uint16_t,
    981 as libc::c_int as uint16_t,
    992 as libc::c_int as uint16_t,
    998 as libc::c_int as uint16_t,
    512 as libc::c_int as uint16_t,
    386 as libc::c_int as uint16_t,
    394 as libc::c_int as uint16_t,
    143 as libc::c_int as uint16_t,
    398 as libc::c_int as uint16_t,
    130 as libc::c_int as uint16_t,
    129 as libc::c_int as uint16_t,
    133 as libc::c_int as uint16_t,
    375 as libc::c_int as uint16_t,
    948 as libc::c_int as uint16_t,
    982 as libc::c_int as uint16_t,
    991 as libc::c_int as uint16_t,
    961 as libc::c_int as uint16_t,
    12 as libc::c_int as uint16_t,
    402 as libc::c_int as uint16_t,
    746 as libc::c_int as uint16_t,
    90 as libc::c_int as uint16_t,
    87 as libc::c_int as uint16_t,
    103 as libc::c_int as uint16_t,
    88 as libc::c_int as uint16_t,
    141 as libc::c_int as uint16_t,
    771 as libc::c_int as uint16_t,
    89 as libc::c_int as uint16_t,
    140 as libc::c_int as uint16_t,
    126 as libc::c_int as uint16_t,
    857 as libc::c_int as uint16_t,
    748 as libc::c_int as uint16_t,
    86 as libc::c_int as uint16_t,
    770 as libc::c_int as uint16_t,
    83 as libc::c_int as uint16_t,
    666 as libc::c_int as uint16_t,
    403 as libc::c_int as uint16_t,
    401 as libc::c_int as uint16_t,
    747 as libc::c_int as uint16_t,
    84 as libc::c_int as uint16_t,
    85 as libc::c_int as uint16_t,
    769 as libc::c_int as uint16_t,
    82 as libc::c_int as uint16_t,
    920 as libc::c_int as uint16_t,
    184 as libc::c_int as uint16_t,
    185 as libc::c_int as uint16_t,
    478 as libc::c_int as uint16_t,
    289 as libc::c_int as uint16_t,
    287 as libc::c_int as uint16_t,
    397 as libc::c_int as uint16_t,
    288 as libc::c_int as uint16_t,
    446 as libc::c_int as uint16_t,
    364 as libc::c_int as uint16_t,
    606 as libc::c_int as uint16_t,
    419 as libc::c_int as uint16_t,
    916 as libc::c_int as uint16_t,
    963 as libc::c_int as uint16_t,
    896 as libc::c_int as uint16_t,
    421 as libc::c_int as uint16_t,
    650 as libc::c_int as uint16_t,
    653 as libc::c_int as uint16_t,
    904 as libc::c_int as uint16_t,
    418 as libc::c_int as uint16_t,
    895 as libc::c_int as uint16_t,
    420 as libc::c_int as uint16_t,
    913 as libc::c_int as uint16_t,
    423 as libc::c_int as uint16_t,
    917 as libc::c_int as uint16_t,
    899 as libc::c_int as uint16_t,
    425 as libc::c_int as uint16_t,
    651 as libc::c_int as uint16_t,
    654 as libc::c_int as uint16_t,
    905 as libc::c_int as uint16_t,
    422 as libc::c_int as uint16_t,
    898 as libc::c_int as uint16_t,
    424 as libc::c_int as uint16_t,
    427 as libc::c_int as uint16_t,
    918 as libc::c_int as uint16_t,
    964 as libc::c_int as uint16_t,
    902 as libc::c_int as uint16_t,
    429 as libc::c_int as uint16_t,
    652 as libc::c_int as uint16_t,
    655 as libc::c_int as uint16_t,
    906 as libc::c_int as uint16_t,
    426 as libc::c_int as uint16_t,
    901 as libc::c_int as uint16_t,
    428 as libc::c_int as uint16_t,
    914 as libc::c_int as uint16_t,
    376 as libc::c_int as uint16_t,
    484 as libc::c_int as uint16_t,
    485 as libc::c_int as uint16_t,
    501 as libc::c_int as uint16_t,
    958 as libc::c_int as uint16_t,
    955 as libc::c_int as uint16_t,
    956 as libc::c_int as uint16_t,
    954 as libc::c_int as uint16_t,
    882 as libc::c_int as uint16_t,
    91 as libc::c_int as uint16_t,
    93 as libc::c_int as uint16_t,
    92 as libc::c_int as uint16_t,
    94 as libc::c_int as uint16_t,
    921 as libc::c_int as uint16_t,
    922 as libc::c_int as uint16_t,
    923 as libc::c_int as uint16_t,
    924 as libc::c_int as uint16_t,
    925 as libc::c_int as uint16_t,
    926 as libc::c_int as uint16_t,
    927 as libc::c_int as uint16_t,
    928 as libc::c_int as uint16_t,
    929 as libc::c_int as uint16_t,
    930 as libc::c_int as uint16_t,
    931 as libc::c_int as uint16_t,
    932 as libc::c_int as uint16_t,
    933 as libc::c_int as uint16_t,
    934 as libc::c_int as uint16_t,
    494 as libc::c_int as uint16_t,
    860 as libc::c_int as uint16_t,
    691 as libc::c_int as uint16_t,
    692 as libc::c_int as uint16_t,
    697 as libc::c_int as uint16_t,
    698 as libc::c_int as uint16_t,
    684 as libc::c_int as uint16_t,
    685 as libc::c_int as uint16_t,
    686 as libc::c_int as uint16_t,
    687 as libc::c_int as uint16_t,
    693 as libc::c_int as uint16_t,
    699 as libc::c_int as uint16_t,
    700 as libc::c_int as uint16_t,
    702 as libc::c_int as uint16_t,
    688 as libc::c_int as uint16_t,
    689 as libc::c_int as uint16_t,
    690 as libc::c_int as uint16_t,
    694 as libc::c_int as uint16_t,
    695 as libc::c_int as uint16_t,
    696 as libc::c_int as uint16_t,
    701 as libc::c_int as uint16_t,
    703 as libc::c_int as uint16_t,
    881 as libc::c_int as uint16_t,
    483 as libc::c_int as uint16_t,
    751 as libc::c_int as uint16_t,
    757 as libc::c_int as uint16_t,
    760 as libc::c_int as uint16_t,
    763 as libc::c_int as uint16_t,
    754 as libc::c_int as uint16_t,
    766 as libc::c_int as uint16_t,
    752 as libc::c_int as uint16_t,
    758 as libc::c_int as uint16_t,
    761 as libc::c_int as uint16_t,
    764 as libc::c_int as uint16_t,
    755 as libc::c_int as uint16_t,
    767 as libc::c_int as uint16_t,
    753 as libc::c_int as uint16_t,
    759 as libc::c_int as uint16_t,
    762 as libc::c_int as uint16_t,
    765 as libc::c_int as uint16_t,
    756 as libc::c_int as uint16_t,
    768 as libc::c_int as uint16_t,
    443 as libc::c_int as uint16_t,
    108 as libc::c_int as uint16_t,
    110 as libc::c_int as uint16_t,
    109 as libc::c_int as uint16_t,
    111 as libc::c_int as uint16_t,
    152 as libc::c_int as uint16_t,
    677 as libc::c_int as uint16_t,
    517 as libc::c_int as uint16_t,
    883 as libc::c_int as uint16_t,
    950 as libc::c_int as uint16_t,
    54 as libc::c_int as uint16_t,
    407 as libc::c_int as uint16_t,
    395 as libc::c_int as uint16_t,
    633 as libc::c_int as uint16_t,
    894 as libc::c_int as uint16_t,
    13 as libc::c_int as uint16_t,
    513 as libc::c_int as uint16_t,
    50 as libc::c_int as uint16_t,
    53 as libc::c_int as uint16_t,
    14 as libc::c_int as uint16_t,
    153 as libc::c_int as uint16_t,
    884 as libc::c_int as uint16_t,
    806 as libc::c_int as uint16_t,
    805 as libc::c_int as uint16_t,
    500 as libc::c_int as uint16_t,
    451 as libc::c_int as uint16_t,
    495 as libc::c_int as uint16_t,
    434 as libc::c_int as uint16_t,
    390 as libc::c_int as uint16_t,
    891 as libc::c_int as uint16_t,
    31 as libc::c_int as uint16_t,
    643 as libc::c_int as uint16_t,
    30 as libc::c_int as uint16_t,
    656 as libc::c_int as uint16_t,
    657 as libc::c_int as uint16_t,
    29 as libc::c_int as uint16_t,
    32 as libc::c_int as uint16_t,
    43 as libc::c_int as uint16_t,
    60 as libc::c_int as uint16_t,
    62 as libc::c_int as uint16_t,
    33 as libc::c_int as uint16_t,
    44 as libc::c_int as uint16_t,
    61 as libc::c_int as uint16_t,
    658 as libc::c_int as uint16_t,
    659 as libc::c_int as uint16_t,
    63 as libc::c_int as uint16_t,
    45 as libc::c_int as uint16_t,
    107 as libc::c_int as uint16_t,
    871 as libc::c_int as uint16_t,
    80 as libc::c_int as uint16_t,
    947 as libc::c_int as uint16_t,
    946 as libc::c_int as uint16_t,
    28 as libc::c_int as uint16_t,
    941 as libc::c_int as uint16_t,
    942 as libc::c_int as uint16_t,
    943 as libc::c_int as uint16_t,
    944 as libc::c_int as uint16_t,
    945 as libc::c_int as uint16_t,
    936 as libc::c_int as uint16_t,
    937 as libc::c_int as uint16_t,
    938 as libc::c_int as uint16_t,
    939 as libc::c_int as uint16_t,
    940 as libc::c_int as uint16_t,
    11 as libc::c_int as uint16_t,
    378 as libc::c_int as uint16_t,
    887 as libc::c_int as uint16_t,
    892 as libc::c_int as uint16_t,
    174 as libc::c_int as uint16_t,
    447 as libc::c_int as uint16_t,
    471 as libc::c_int as uint16_t,
    468 as libc::c_int as uint16_t,
    472 as libc::c_int as uint16_t,
    502 as libc::c_int as uint16_t,
    449 as libc::c_int as uint16_t,
    469 as libc::c_int as uint16_t,
    470 as libc::c_int as uint16_t,
    380 as libc::c_int as uint16_t,
    391 as libc::c_int as uint16_t,
    452 as libc::c_int as uint16_t,
    116 as libc::c_int as uint16_t,
    67 as libc::c_int as uint16_t,
    66 as libc::c_int as uint16_t,
    113 as libc::c_int as uint16_t,
    70 as libc::c_int as uint16_t,
    802 as libc::c_int as uint16_t,
    803 as libc::c_int as uint16_t,
    297 as libc::c_int as uint16_t,
    791 as libc::c_int as uint16_t,
    416 as libc::c_int as uint16_t,
    793 as libc::c_int as uint16_t,
    794 as libc::c_int as uint16_t,
    795 as libc::c_int as uint16_t,
    796 as libc::c_int as uint16_t,
    792 as libc::c_int as uint16_t,
    48 as libc::c_int as uint16_t,
    632 as libc::c_int as uint16_t,
    885 as libc::c_int as uint16_t,
    56 as libc::c_int as uint16_t,
    867 as libc::c_int as uint16_t,
    462 as libc::c_int as uint16_t,
    976 as libc::c_int as uint16_t,
    983 as libc::c_int as uint16_t,
    977 as libc::c_int as uint16_t,
    984 as libc::c_int as uint16_t,
    453 as libc::c_int as uint16_t,
    490 as libc::c_int as uint16_t,
    156 as libc::c_int as uint16_t,
    631 as libc::c_int as uint16_t,
    509 as libc::c_int as uint16_t,
    601 as libc::c_int as uint16_t,
    99 as libc::c_int as uint16_t,
    814 as libc::c_int as uint16_t,
    969 as libc::c_int as uint16_t,
    855 as libc::c_int as uint16_t,
    780 as libc::c_int as uint16_t,
    781 as libc::c_int as uint16_t,
    797 as libc::c_int as uint16_t,
    163 as libc::c_int as uint16_t,
    798 as libc::c_int as uint16_t,
    799 as libc::c_int as uint16_t,
    800 as libc::c_int as uint16_t,
    801 as libc::c_int as uint16_t,
    486 as libc::c_int as uint16_t,
    473 as libc::c_int as uint16_t,
    466 as libc::c_int as uint16_t,
    889 as libc::c_int as uint16_t,
    442 as libc::c_int as uint16_t,
    381 as libc::c_int as uint16_t,
    824 as libc::c_int as uint16_t,
    825 as libc::c_int as uint16_t,
    826 as libc::c_int as uint16_t,
    827 as libc::c_int as uint16_t,
    819 as libc::c_int as uint16_t,
    829 as libc::c_int as uint16_t,
    828 as libc::c_int as uint16_t,
    830 as libc::c_int as uint16_t,
    820 as libc::c_int as uint16_t,
    823 as libc::c_int as uint16_t,
    840 as libc::c_int as uint16_t,
    841 as libc::c_int as uint16_t,
    842 as libc::c_int as uint16_t,
    843 as libc::c_int as uint16_t,
    844 as libc::c_int as uint16_t,
    839 as libc::c_int as uint16_t,
    832 as libc::c_int as uint16_t,
    833 as libc::c_int as uint16_t,
    834 as libc::c_int as uint16_t,
    835 as libc::c_int as uint16_t,
    836 as libc::c_int as uint16_t,
    837 as libc::c_int as uint16_t,
    838 as libc::c_int as uint16_t,
    831 as libc::c_int as uint16_t,
    845 as libc::c_int as uint16_t,
    846 as libc::c_int as uint16_t,
    847 as libc::c_int as uint16_t,
    848 as libc::c_int as uint16_t,
    822 as libc::c_int as uint16_t,
    821 as libc::c_int as uint16_t,
    266 as libc::c_int as uint16_t,
    355 as libc::c_int as uint16_t,
    354 as libc::c_int as uint16_t,
    356 as libc::c_int as uint16_t,
    399 as libc::c_int as uint16_t,
    357 as libc::c_int as uint16_t,
    358 as libc::c_int as uint16_t,
    176 as libc::c_int as uint16_t,
    788 as libc::c_int as uint16_t,
    897 as libc::c_int as uint16_t,
    789 as libc::c_int as uint16_t,
    900 as libc::c_int as uint16_t,
    790 as libc::c_int as uint16_t,
    903 as libc::c_int as uint16_t,
    262 as libc::c_int as uint16_t,
    893 as libc::c_int as uint16_t,
    323 as libc::c_int as uint16_t,
    326 as libc::c_int as uint16_t,
    325 as libc::c_int as uint16_t,
    324 as libc::c_int as uint16_t,
    907 as libc::c_int as uint16_t,
    908 as libc::c_int as uint16_t,
    909 as libc::c_int as uint16_t,
    268 as libc::c_int as uint16_t,
    361 as libc::c_int as uint16_t,
    362 as libc::c_int as uint16_t,
    360 as libc::c_int as uint16_t,
    81 as libc::c_int as uint16_t,
    680 as libc::c_int as uint16_t,
    263 as libc::c_int as uint16_t,
    334 as libc::c_int as uint16_t,
    346 as libc::c_int as uint16_t,
    330 as libc::c_int as uint16_t,
    336 as libc::c_int as uint16_t,
    335 as libc::c_int as uint16_t,
    339 as libc::c_int as uint16_t,
    338 as libc::c_int as uint16_t,
    328 as libc::c_int as uint16_t,
    329 as libc::c_int as uint16_t,
    337 as libc::c_int as uint16_t,
    344 as libc::c_int as uint16_t,
    345 as libc::c_int as uint16_t,
    343 as libc::c_int as uint16_t,
    333 as libc::c_int as uint16_t,
    341 as libc::c_int as uint16_t,
    342 as libc::c_int as uint16_t,
    340 as libc::c_int as uint16_t,
    332 as libc::c_int as uint16_t,
    327 as libc::c_int as uint16_t,
    331 as libc::c_int as uint16_t,
    787 as libc::c_int as uint16_t,
    408 as libc::c_int as uint16_t,
    508 as libc::c_int as uint16_t,
    507 as libc::c_int as uint16_t,
    260 as libc::c_int as uint16_t,
    302 as libc::c_int as uint16_t,
    298 as libc::c_int as uint16_t,
    311 as libc::c_int as uint16_t,
    303 as libc::c_int as uint16_t,
    300 as libc::c_int as uint16_t,
    310 as libc::c_int as uint16_t,
    308 as libc::c_int as uint16_t,
    307 as libc::c_int as uint16_t,
    312 as libc::c_int as uint16_t,
    301 as libc::c_int as uint16_t,
    309 as libc::c_int as uint16_t,
    299 as libc::c_int as uint16_t,
    305 as libc::c_int as uint16_t,
    306 as libc::c_int as uint16_t,
    784 as libc::c_int as uint16_t,
    304 as libc::c_int as uint16_t,
    128 as libc::c_int as uint16_t,
    280 as libc::c_int as uint16_t,
    274 as libc::c_int as uint16_t,
    277 as libc::c_int as uint16_t,
    284 as libc::c_int as uint16_t,
    273 as libc::c_int as uint16_t,
    283 as libc::c_int as uint16_t,
    275 as libc::c_int as uint16_t,
    276 as libc::c_int as uint16_t,
    282 as libc::c_int as uint16_t,
    278 as libc::c_int as uint16_t,
    279 as libc::c_int as uint16_t,
    281 as libc::c_int as uint16_t,
    264 as libc::c_int as uint16_t,
    347 as libc::c_int as uint16_t,
    265 as libc::c_int as uint16_t,
    352 as libc::c_int as uint16_t,
    353 as libc::c_int as uint16_t,
    348 as libc::c_int as uint16_t,
    351 as libc::c_int as uint16_t,
    349 as libc::c_int as uint16_t,
    175 as libc::c_int as uint16_t,
    261 as libc::c_int as uint16_t,
    258 as libc::c_int as uint16_t,
    269 as libc::c_int as uint16_t,
    271 as libc::c_int as uint16_t,
    270 as libc::c_int as uint16_t,
    272 as libc::c_int as uint16_t,
    662 as libc::c_int as uint16_t,
    267 as libc::c_int as uint16_t,
    359 as libc::c_int as uint16_t,
    259 as libc::c_int as uint16_t,
    313 as libc::c_int as uint16_t,
    316 as libc::c_int as uint16_t,
    319 as libc::c_int as uint16_t,
    318 as libc::c_int as uint16_t,
    317 as libc::c_int as uint16_t,
    320 as libc::c_int as uint16_t,
    315 as libc::c_int as uint16_t,
    314 as libc::c_int as uint16_t,
    322 as libc::c_int as uint16_t,
    321 as libc::c_int as uint16_t,
    191 as libc::c_int as uint16_t,
    215 as libc::c_int as uint16_t,
    218 as libc::c_int as uint16_t,
    221 as libc::c_int as uint16_t,
    240 as libc::c_int as uint16_t,
    217 as libc::c_int as uint16_t,
    222 as libc::c_int as uint16_t,
    220 as libc::c_int as uint16_t,
    232 as libc::c_int as uint16_t,
    233 as libc::c_int as uint16_t,
    238 as libc::c_int as uint16_t,
    237 as libc::c_int as uint16_t,
    234 as libc::c_int as uint16_t,
    227 as libc::c_int as uint16_t,
    231 as libc::c_int as uint16_t,
    236 as libc::c_int as uint16_t,
    230 as libc::c_int as uint16_t,
    235 as libc::c_int as uint16_t,
    226 as libc::c_int as uint16_t,
    229 as libc::c_int as uint16_t,
    228 as libc::c_int as uint16_t,
    219 as libc::c_int as uint16_t,
    214 as libc::c_int as uint16_t,
    216 as libc::c_int as uint16_t,
    212 as libc::c_int as uint16_t,
    213 as libc::c_int as uint16_t,
    239 as libc::c_int as uint16_t,
    223 as libc::c_int as uint16_t,
    224 as libc::c_int as uint16_t,
    225 as libc::c_int as uint16_t,
    192 as libc::c_int as uint16_t,
    243 as libc::c_int as uint16_t,
    246 as libc::c_int as uint16_t,
    247 as libc::c_int as uint16_t,
    245 as libc::c_int as uint16_t,
    241 as libc::c_int as uint16_t,
    242 as libc::c_int as uint16_t,
    244 as libc::c_int as uint16_t,
    193 as libc::c_int as uint16_t,
    248 as libc::c_int as uint16_t,
    190 as libc::c_int as uint16_t,
    210 as libc::c_int as uint16_t,
    211 as libc::c_int as uint16_t,
    208 as libc::c_int as uint16_t,
    207 as libc::c_int as uint16_t,
    205 as libc::c_int as uint16_t,
    786 as libc::c_int as uint16_t,
    209 as libc::c_int as uint16_t,
    206 as libc::c_int as uint16_t,
    204 as libc::c_int as uint16_t,
    195 as libc::c_int as uint16_t,
    255 as libc::c_int as uint16_t,
    256 as libc::c_int as uint16_t,
    253 as libc::c_int as uint16_t,
    251 as libc::c_int as uint16_t,
    252 as libc::c_int as uint16_t,
    254 as libc::c_int as uint16_t,
    189 as libc::c_int as uint16_t,
    196 as libc::c_int as uint16_t,
    197 as libc::c_int as uint16_t,
    202 as libc::c_int as uint16_t,
    203 as libc::c_int as uint16_t,
    200 as libc::c_int as uint16_t,
    201 as libc::c_int as uint16_t,
    199 as libc::c_int as uint16_t,
    198 as libc::c_int as uint16_t,
    194 as libc::c_int as uint16_t,
    250 as libc::c_int as uint16_t,
    249 as libc::c_int as uint16_t,
    34 as libc::c_int as uint16_t,
    35 as libc::c_int as uint16_t,
    36 as libc::c_int as uint16_t,
    46 as libc::c_int as uint16_t,
    676 as libc::c_int as uint16_t,
    461 as libc::c_int as uint16_t,
    101 as libc::c_int as uint16_t,
    869 as libc::c_int as uint16_t,
    749 as libc::c_int as uint16_t,
    750 as libc::c_int as uint16_t,
    181 as libc::c_int as uint16_t,
    623 as libc::c_int as uint16_t,
    645 as libc::c_int as uint16_t,
    492 as libc::c_int as uint16_t,
    646 as libc::c_int as uint16_t,
    970 as libc::c_int as uint16_t,
    150 as libc::c_int as uint16_t,
    773 as libc::c_int as uint16_t,
    957 as libc::c_int as uint16_t,
    952 as libc::c_int as uint16_t,
    953 as libc::c_int as uint16_t,
    951 as libc::c_int as uint16_t,
    477 as libc::c_int as uint16_t,
    476 as libc::c_int as uint16_t,
    157 as libc::c_int as uint16_t,
    15 as libc::c_int as uint16_t,
    480 as libc::c_int as uint16_t,
    493 as libc::c_int as uint16_t,
    467 as libc::c_int as uint16_t,
    3 as libc::c_int as uint16_t,
    7 as libc::c_int as uint16_t,
    257 as libc::c_int as uint16_t,
    396 as libc::c_int as uint16_t,
    4 as libc::c_int as uint16_t,
    114 as libc::c_int as uint16_t,
    104 as libc::c_int as uint16_t,
    8 as libc::c_int as uint16_t,
    95 as libc::c_int as uint16_t,
    96 as libc::c_int as uint16_t,
    875 as libc::c_int as uint16_t,
    602 as libc::c_int as uint16_t,
    514 as libc::c_int as uint16_t,
    51 as libc::c_int as uint16_t,
    911 as libc::c_int as uint16_t,
    506 as libc::c_int as uint16_t,
    505 as libc::c_int as uint16_t,
    488 as libc::c_int as uint16_t,
    481 as libc::c_int as uint16_t,
    173 as libc::c_int as uint16_t,
    681 as libc::c_int as uint16_t,
    379 as libc::c_int as uint16_t,
    17 as libc::c_int as uint16_t,
    491 as libc::c_int as uint16_t,
    18 as libc::c_int as uint16_t,
    475 as libc::c_int as uint16_t,
    876 as libc::c_int as uint16_t,
    935 as libc::c_int as uint16_t,
    489 as libc::c_int as uint16_t,
    782 as libc::c_int as uint16_t,
    374 as libc::c_int as uint16_t,
    621 as libc::c_int as uint16_t,
    9 as libc::c_int as uint16_t,
    168 as libc::c_int as uint16_t,
    112 as libc::c_int as uint16_t,
    10 as libc::c_int as uint16_t,
    169 as libc::c_int as uint16_t,
    148 as libc::c_int as uint16_t,
    144 as libc::c_int as uint16_t,
    147 as libc::c_int as uint16_t,
    146 as libc::c_int as uint16_t,
    149 as libc::c_int as uint16_t,
    145 as libc::c_int as uint16_t,
    170 as libc::c_int as uint16_t,
    68 as libc::c_int as uint16_t,
    499 as libc::c_int as uint16_t,
    487 as libc::c_int as uint16_t,
    464 as libc::c_int as uint16_t,
    863 as libc::c_int as uint16_t,
    437 as libc::c_int as uint16_t,
    439 as libc::c_int as uint16_t,
    438 as libc::c_int as uint16_t,
    479 as libc::c_int as uint16_t,
    456 as libc::c_int as uint16_t,
    441 as libc::c_int as uint16_t,
    444 as libc::c_int as uint16_t,
    440 as libc::c_int as uint16_t,
    455 as libc::c_int as uint16_t,
    445 as libc::c_int as uint16_t,
    186 as libc::c_int as uint16_t,
    27 as libc::c_int as uint16_t,
    187 as libc::c_int as uint16_t,
    20 as libc::c_int as uint16_t,
    21 as libc::c_int as uint16_t,
    25 as libc::c_int as uint16_t,
    26 as libc::c_int as uint16_t,
    23 as libc::c_int as uint16_t,
    24 as libc::c_int as uint16_t,
    22 as libc::c_int as uint16_t,
    151 as libc::c_int as uint16_t,
    47 as libc::c_int as uint16_t,
    862 as libc::c_int as uint16_t,
    861 as libc::c_int as uint16_t,
    661 as libc::c_int as uint16_t,
    683 as libc::c_int as uint16_t,
    872 as libc::c_int as uint16_t,
    873 as libc::c_int as uint16_t,
    406 as libc::c_int as uint16_t,
    409 as libc::c_int as uint16_t,
    410 as libc::c_int as uint16_t,
    411 as libc::c_int as uint16_t,
    412 as libc::c_int as uint16_t,
    413 as libc::c_int as uint16_t,
    414 as libc::c_int as uint16_t,
    415 as libc::c_int as uint16_t,
    886 as libc::c_int as uint16_t,
    510 as libc::c_int as uint16_t,
    435 as libc::c_int as uint16_t,
    286 as libc::c_int as uint16_t,
    457 as libc::c_int as uint16_t,
    450 as libc::c_int as uint16_t,
    98 as libc::c_int as uint16_t,
    166 as libc::c_int as uint16_t,
    37 as libc::c_int as uint16_t,
    39 as libc::c_int as uint16_t,
    38 as libc::c_int as uint16_t,
    40 as libc::c_int as uint16_t,
    5 as libc::c_int as uint16_t,
    97 as libc::c_int as uint16_t,
    915 as libc::c_int as uint16_t,
    120 as libc::c_int as uint16_t,
    122 as libc::c_int as uint16_t,
    121 as libc::c_int as uint16_t,
    123 as libc::c_int as uint16_t,
    870 as libc::c_int as uint16_t,
    460 as libc::c_int as uint16_t,
    117 as libc::c_int as uint16_t,
    119 as libc::c_int as uint16_t,
    400 as libc::c_int as uint16_t,
    877 as libc::c_int as uint16_t,
    448 as libc::c_int as uint16_t,
    463 as libc::c_int as uint16_t,
    19 as libc::c_int as uint16_t,
    6 as libc::c_int as uint16_t,
    644 as libc::c_int as uint16_t,
    377 as libc::c_int as uint16_t,
    919 as libc::c_int as uint16_t,
    912 as libc::c_int as uint16_t,
    482 as libc::c_int as uint16_t,
    155 as libc::c_int as uint16_t,
    291 as libc::c_int as uint16_t,
    290 as libc::c_int as uint16_t,
    292 as libc::c_int as uint16_t,
    159 as libc::c_int as uint16_t,
    859 as libc::c_int as uint16_t,
    704 as libc::c_int as uint16_t,
    705 as libc::c_int as uint16_t,
    706 as libc::c_int as uint16_t,
    707 as libc::c_int as uint16_t,
    708 as libc::c_int as uint16_t,
    709 as libc::c_int as uint16_t,
    710 as libc::c_int as uint16_t,
    711 as libc::c_int as uint16_t,
    712 as libc::c_int as uint16_t,
    713 as libc::c_int as uint16_t,
    714 as libc::c_int as uint16_t,
    715 as libc::c_int as uint16_t,
    716 as libc::c_int as uint16_t,
    154 as libc::c_int as uint16_t,
    474 as libc::c_int as uint16_t,
    717 as libc::c_int as uint16_t,
    718 as libc::c_int as uint16_t,
    719 as libc::c_int as uint16_t,
    720 as libc::c_int as uint16_t,
    721 as libc::c_int as uint16_t,
    722 as libc::c_int as uint16_t,
    723 as libc::c_int as uint16_t,
    724 as libc::c_int as uint16_t,
    725 as libc::c_int as uint16_t,
    726 as libc::c_int as uint16_t,
    727 as libc::c_int as uint16_t,
    728 as libc::c_int as uint16_t,
    729 as libc::c_int as uint16_t,
    730 as libc::c_int as uint16_t,
    731 as libc::c_int as uint16_t,
    732 as libc::c_int as uint16_t,
    733 as libc::c_int as uint16_t,
    734 as libc::c_int as uint16_t,
    635 as libc::c_int as uint16_t,
    878 as libc::c_int as uint16_t,
    777 as libc::c_int as uint16_t,
    779 as libc::c_int as uint16_t,
    776 as libc::c_int as uint16_t,
    778 as libc::c_int as uint16_t,
    105 as libc::c_int as uint16_t,
    625 as libc::c_int as uint16_t,
    515 as libc::c_int as uint16_t,
    518 as libc::c_int as uint16_t,
    638 as libc::c_int as uint16_t,
    637 as libc::c_int as uint16_t,
    636 as libc::c_int as uint16_t,
    639 as libc::c_int as uint16_t,
    641 as libc::c_int as uint16_t,
    642 as libc::c_int as uint16_t,
    640 as libc::c_int as uint16_t,
    516 as libc::c_int as uint16_t,
    607 as libc::c_int as uint16_t,
    624 as libc::c_int as uint16_t,
    620 as libc::c_int as uint16_t,
    628 as libc::c_int as uint16_t,
    630 as libc::c_int as uint16_t,
    629 as libc::c_int as uint16_t,
    627 as libc::c_int as uint16_t,
    626 as libc::c_int as uint16_t,
    622 as libc::c_int as uint16_t,
    619 as libc::c_int as uint16_t,
    615 as libc::c_int as uint16_t,
    616 as libc::c_int as uint16_t,
    618 as libc::c_int as uint16_t,
    617 as libc::c_int as uint16_t,
    611 as libc::c_int as uint16_t,
    609 as libc::c_int as uint16_t,
    608 as libc::c_int as uint16_t,
    610 as libc::c_int as uint16_t,
    613 as libc::c_int as uint16_t,
    614 as libc::c_int as uint16_t,
    612 as libc::c_int as uint16_t,
    540 as libc::c_int as uint16_t,
    576 as libc::c_int as uint16_t,
    570 as libc::c_int as uint16_t,
    534 as libc::c_int as uint16_t,
    527 as libc::c_int as uint16_t,
    571 as libc::c_int as uint16_t,
    572 as libc::c_int as uint16_t,
    535 as libc::c_int as uint16_t,
    536 as libc::c_int as uint16_t,
    528 as libc::c_int as uint16_t,
    577 as libc::c_int as uint16_t,
    541 as libc::c_int as uint16_t,
    529 as libc::c_int as uint16_t,
    542 as libc::c_int as uint16_t,
    578 as libc::c_int as uint16_t,
    579 as libc::c_int as uint16_t,
    543 as libc::c_int as uint16_t,
    573 as libc::c_int as uint16_t,
    537 as libc::c_int as uint16_t,
    600 as libc::c_int as uint16_t,
    558 as libc::c_int as uint16_t,
    592 as libc::c_int as uint16_t,
    559 as libc::c_int as uint16_t,
    593 as libc::c_int as uint16_t,
    599 as libc::c_int as uint16_t,
    598 as libc::c_int as uint16_t,
    580 as libc::c_int as uint16_t,
    581 as libc::c_int as uint16_t,
    544 as libc::c_int as uint16_t,
    545 as libc::c_int as uint16_t,
    546 as libc::c_int as uint16_t,
    582 as libc::c_int as uint16_t,
    583 as libc::c_int as uint16_t,
    584 as libc::c_int as uint16_t,
    547 as libc::c_int as uint16_t,
    548 as libc::c_int as uint16_t,
    549 as libc::c_int as uint16_t,
    585 as libc::c_int as uint16_t,
    538 as libc::c_int as uint16_t,
    530 as libc::c_int as uint16_t,
    574 as libc::c_int as uint16_t,
    575 as libc::c_int as uint16_t,
    539 as libc::c_int as uint16_t,
    560 as libc::c_int as uint16_t,
    566 as libc::c_int as uint16_t,
    563 as libc::c_int as uint16_t,
    595 as libc::c_int as uint16_t,
    596 as libc::c_int as uint16_t,
    564 as libc::c_int as uint16_t,
    565 as libc::c_int as uint16_t,
    597 as libc::c_int as uint16_t,
    586 as libc::c_int as uint16_t,
    587 as libc::c_int as uint16_t,
    550 as libc::c_int as uint16_t,
    551 as libc::c_int as uint16_t,
    552 as libc::c_int as uint16_t,
    588 as libc::c_int as uint16_t,
    589 as libc::c_int as uint16_t,
    590 as libc::c_int as uint16_t,
    553 as libc::c_int as uint16_t,
    554 as libc::c_int as uint16_t,
    555 as libc::c_int as uint16_t,
    591 as libc::c_int as uint16_t,
    567 as libc::c_int as uint16_t,
    526 as libc::c_int as uint16_t,
    561 as libc::c_int as uint16_t,
    522 as libc::c_int as uint16_t,
    519 as libc::c_int as uint16_t,
    521 as libc::c_int as uint16_t,
    520 as libc::c_int as uint16_t,
    556 as libc::c_int as uint16_t,
    557 as libc::c_int as uint16_t,
    523 as libc::c_int as uint16_t,
    532 as libc::c_int as uint16_t,
    524 as libc::c_int as uint16_t,
    525 as libc::c_int as uint16_t,
    568 as libc::c_int as uint16_t,
    569 as libc::c_int as uint16_t,
    531 as libc::c_int as uint16_t,
    533 as libc::c_int as uint16_t,
    594 as libc::c_int as uint16_t,
    562 as libc::c_int as uint16_t,
    604 as libc::c_int as uint16_t,
    603 as libc::c_int as uint16_t,
    605 as libc::c_int as uint16_t,
    41 as libc::c_int as uint16_t,
    64 as libc::c_int as uint16_t,
    115 as libc::c_int as uint16_t,
    65 as libc::c_int as uint16_t,
    675 as libc::c_int as uint16_t,
    671 as libc::c_int as uint16_t,
    672 as libc::c_int as uint16_t,
    668 as libc::c_int as uint16_t,
    965 as libc::c_int as uint16_t,
    966 as libc::c_int as uint16_t,
    967 as libc::c_int as uint16_t,
    968 as libc::c_int as uint16_t,
    673 as libc::c_int as uint16_t,
    669 as libc::c_int as uint16_t,
    674 as libc::c_int as uint16_t,
    978 as libc::c_int as uint16_t,
    962 as libc::c_int as uint16_t,
    670 as libc::c_int as uint16_t,
    42 as libc::c_int as uint16_t,
    979 as libc::c_int as uint16_t,
    980 as libc::c_int as uint16_t,
    52 as libc::c_int as uint16_t,
    454 as libc::c_int as uint16_t,
    496 as libc::c_int as uint16_t,
    16 as libc::c_int as uint16_t,
    660 as libc::c_int as uint16_t,
    498 as libc::c_int as uint16_t,
    497 as libc::c_int as uint16_t,
    890 as libc::c_int as uint16_t,
    874 as libc::c_int as uint16_t,
    100 as libc::c_int as uint16_t,
    864 as libc::c_int as uint16_t,
    866 as libc::c_int as uint16_t,
    865 as libc::c_int as uint16_t,
    459 as libc::c_int as uint16_t,
    293 as libc::c_int as uint16_t,
    106 as libc::c_int as uint16_t,
    682 as libc::c_int as uint16_t,
    436 as libc::c_int as uint16_t,
    888 as libc::c_int as uint16_t,
    55 as libc::c_int as uint16_t,
    49 as libc::c_int as uint16_t,
    880 as libc::c_int as uint16_t,
    465 as libc::c_int as uint16_t,
    458 as libc::c_int as uint16_t,
    879 as libc::c_int as uint16_t,
    373 as libc::c_int as uint16_t,
    678 as libc::c_int as uint16_t,
    679 as libc::c_int as uint16_t,
    735 as libc::c_int as uint16_t,
    743 as libc::c_int as uint16_t,
    744 as libc::c_int as uint16_t,
    745 as libc::c_int as uint16_t,
    736 as libc::c_int as uint16_t,
    737 as libc::c_int as uint16_t,
    738 as libc::c_int as uint16_t,
    739 as libc::c_int as uint16_t,
    740 as libc::c_int as uint16_t,
    741 as libc::c_int as uint16_t,
    742 as libc::c_int as uint16_t,
    804 as libc::c_int as uint16_t,
    868 as libc::c_int as uint16_t,
    503 as libc::c_int as uint16_t,
    158 as libc::c_int as uint16_t,
    160 as libc::c_int as uint16_t,
    125 as libc::c_int as uint16_t,
];
static mut kNIDsInOIDOrder: [uint16_t; 902] = [
    434 as libc::c_int as uint16_t,
    182 as libc::c_int as uint16_t,
    379 as libc::c_int as uint16_t,
    676 as libc::c_int as uint16_t,
    11 as libc::c_int as uint16_t,
    647 as libc::c_int as uint16_t,
    380 as libc::c_int as uint16_t,
    12 as libc::c_int as uint16_t,
    378 as libc::c_int as uint16_t,
    81 as libc::c_int as uint16_t,
    512 as libc::c_int as uint16_t,
    678 as libc::c_int as uint16_t,
    435 as libc::c_int as uint16_t,
    183 as libc::c_int as uint16_t,
    381 as libc::c_int as uint16_t,
    948 as libc::c_int as uint16_t,
    961 as libc::c_int as uint16_t,
    949 as libc::c_int as uint16_t,
    960 as libc::c_int as uint16_t,
    677 as libc::c_int as uint16_t,
    394 as libc::c_int as uint16_t,
    13 as libc::c_int as uint16_t,
    100 as libc::c_int as uint16_t,
    105 as libc::c_int as uint16_t,
    14 as libc::c_int as uint16_t,
    15 as libc::c_int as uint16_t,
    16 as libc::c_int as uint16_t,
    660 as libc::c_int as uint16_t,
    17 as libc::c_int as uint16_t,
    18 as libc::c_int as uint16_t,
    106 as libc::c_int as uint16_t,
    107 as libc::c_int as uint16_t,
    859 as libc::c_int as uint16_t,
    860 as libc::c_int as uint16_t,
    861 as libc::c_int as uint16_t,
    661 as libc::c_int as uint16_t,
    862 as libc::c_int as uint16_t,
    863 as libc::c_int as uint16_t,
    864 as libc::c_int as uint16_t,
    865 as libc::c_int as uint16_t,
    866 as libc::c_int as uint16_t,
    867 as libc::c_int as uint16_t,
    868 as libc::c_int as uint16_t,
    869 as libc::c_int as uint16_t,
    870 as libc::c_int as uint16_t,
    871 as libc::c_int as uint16_t,
    872 as libc::c_int as uint16_t,
    873 as libc::c_int as uint16_t,
    874 as libc::c_int as uint16_t,
    875 as libc::c_int as uint16_t,
    876 as libc::c_int as uint16_t,
    877 as libc::c_int as uint16_t,
    878 as libc::c_int as uint16_t,
    879 as libc::c_int as uint16_t,
    880 as libc::c_int as uint16_t,
    881 as libc::c_int as uint16_t,
    882 as libc::c_int as uint16_t,
    883 as libc::c_int as uint16_t,
    884 as libc::c_int as uint16_t,
    173 as libc::c_int as uint16_t,
    99 as libc::c_int as uint16_t,
    101 as libc::c_int as uint16_t,
    509 as libc::c_int as uint16_t,
    503 as libc::c_int as uint16_t,
    174 as libc::c_int as uint16_t,
    885 as libc::c_int as uint16_t,
    886 as libc::c_int as uint16_t,
    887 as libc::c_int as uint16_t,
    888 as libc::c_int as uint16_t,
    889 as libc::c_int as uint16_t,
    890 as libc::c_int as uint16_t,
    891 as libc::c_int as uint16_t,
    892 as libc::c_int as uint16_t,
    510 as libc::c_int as uint16_t,
    400 as libc::c_int as uint16_t,
    769 as libc::c_int as uint16_t,
    82 as libc::c_int as uint16_t,
    83 as libc::c_int as uint16_t,
    84 as libc::c_int as uint16_t,
    85 as libc::c_int as uint16_t,
    86 as libc::c_int as uint16_t,
    87 as libc::c_int as uint16_t,
    88 as libc::c_int as uint16_t,
    141 as libc::c_int as uint16_t,
    430 as libc::c_int as uint16_t,
    142 as libc::c_int as uint16_t,
    140 as libc::c_int as uint16_t,
    770 as libc::c_int as uint16_t,
    771 as libc::c_int as uint16_t,
    666 as libc::c_int as uint16_t,
    103 as libc::c_int as uint16_t,
    89 as libc::c_int as uint16_t,
    747 as libc::c_int as uint16_t,
    90 as libc::c_int as uint16_t,
    401 as libc::c_int as uint16_t,
    126 as libc::c_int as uint16_t,
    857 as libc::c_int as uint16_t,
    748 as libc::c_int as uint16_t,
    402 as libc::c_int as uint16_t,
    403 as libc::c_int as uint16_t,
    513 as libc::c_int as uint16_t,
    514 as libc::c_int as uint16_t,
    515 as libc::c_int as uint16_t,
    516 as libc::c_int as uint16_t,
    517 as libc::c_int as uint16_t,
    518 as libc::c_int as uint16_t,
    679 as libc::c_int as uint16_t,
    382 as libc::c_int as uint16_t,
    383 as libc::c_int as uint16_t,
    384 as libc::c_int as uint16_t,
    385 as libc::c_int as uint16_t,
    386 as libc::c_int as uint16_t,
    387 as libc::c_int as uint16_t,
    388 as libc::c_int as uint16_t,
    376 as libc::c_int as uint16_t,
    395 as libc::c_int as uint16_t,
    19 as libc::c_int as uint16_t,
    96 as libc::c_int as uint16_t,
    95 as libc::c_int as uint16_t,
    746 as libc::c_int as uint16_t,
    910 as libc::c_int as uint16_t,
    519 as libc::c_int as uint16_t,
    520 as libc::c_int as uint16_t,
    521 as libc::c_int as uint16_t,
    522 as libc::c_int as uint16_t,
    523 as libc::c_int as uint16_t,
    524 as libc::c_int as uint16_t,
    525 as libc::c_int as uint16_t,
    526 as libc::c_int as uint16_t,
    527 as libc::c_int as uint16_t,
    528 as libc::c_int as uint16_t,
    529 as libc::c_int as uint16_t,
    530 as libc::c_int as uint16_t,
    531 as libc::c_int as uint16_t,
    532 as libc::c_int as uint16_t,
    533 as libc::c_int as uint16_t,
    534 as libc::c_int as uint16_t,
    535 as libc::c_int as uint16_t,
    536 as libc::c_int as uint16_t,
    537 as libc::c_int as uint16_t,
    538 as libc::c_int as uint16_t,
    539 as libc::c_int as uint16_t,
    540 as libc::c_int as uint16_t,
    541 as libc::c_int as uint16_t,
    542 as libc::c_int as uint16_t,
    543 as libc::c_int as uint16_t,
    544 as libc::c_int as uint16_t,
    545 as libc::c_int as uint16_t,
    546 as libc::c_int as uint16_t,
    547 as libc::c_int as uint16_t,
    548 as libc::c_int as uint16_t,
    549 as libc::c_int as uint16_t,
    550 as libc::c_int as uint16_t,
    551 as libc::c_int as uint16_t,
    552 as libc::c_int as uint16_t,
    553 as libc::c_int as uint16_t,
    554 as libc::c_int as uint16_t,
    555 as libc::c_int as uint16_t,
    556 as libc::c_int as uint16_t,
    557 as libc::c_int as uint16_t,
    558 as libc::c_int as uint16_t,
    559 as libc::c_int as uint16_t,
    560 as libc::c_int as uint16_t,
    561 as libc::c_int as uint16_t,
    562 as libc::c_int as uint16_t,
    563 as libc::c_int as uint16_t,
    564 as libc::c_int as uint16_t,
    565 as libc::c_int as uint16_t,
    566 as libc::c_int as uint16_t,
    567 as libc::c_int as uint16_t,
    568 as libc::c_int as uint16_t,
    569 as libc::c_int as uint16_t,
    570 as libc::c_int as uint16_t,
    571 as libc::c_int as uint16_t,
    572 as libc::c_int as uint16_t,
    573 as libc::c_int as uint16_t,
    574 as libc::c_int as uint16_t,
    575 as libc::c_int as uint16_t,
    576 as libc::c_int as uint16_t,
    577 as libc::c_int as uint16_t,
    578 as libc::c_int as uint16_t,
    579 as libc::c_int as uint16_t,
    580 as libc::c_int as uint16_t,
    581 as libc::c_int as uint16_t,
    582 as libc::c_int as uint16_t,
    583 as libc::c_int as uint16_t,
    584 as libc::c_int as uint16_t,
    585 as libc::c_int as uint16_t,
    586 as libc::c_int as uint16_t,
    587 as libc::c_int as uint16_t,
    588 as libc::c_int as uint16_t,
    589 as libc::c_int as uint16_t,
    590 as libc::c_int as uint16_t,
    591 as libc::c_int as uint16_t,
    592 as libc::c_int as uint16_t,
    593 as libc::c_int as uint16_t,
    594 as libc::c_int as uint16_t,
    595 as libc::c_int as uint16_t,
    596 as libc::c_int as uint16_t,
    597 as libc::c_int as uint16_t,
    598 as libc::c_int as uint16_t,
    599 as libc::c_int as uint16_t,
    600 as libc::c_int as uint16_t,
    601 as libc::c_int as uint16_t,
    602 as libc::c_int as uint16_t,
    603 as libc::c_int as uint16_t,
    604 as libc::c_int as uint16_t,
    605 as libc::c_int as uint16_t,
    606 as libc::c_int as uint16_t,
    620 as libc::c_int as uint16_t,
    621 as libc::c_int as uint16_t,
    622 as libc::c_int as uint16_t,
    623 as libc::c_int as uint16_t,
    607 as libc::c_int as uint16_t,
    608 as libc::c_int as uint16_t,
    609 as libc::c_int as uint16_t,
    610 as libc::c_int as uint16_t,
    611 as libc::c_int as uint16_t,
    612 as libc::c_int as uint16_t,
    613 as libc::c_int as uint16_t,
    614 as libc::c_int as uint16_t,
    615 as libc::c_int as uint16_t,
    616 as libc::c_int as uint16_t,
    617 as libc::c_int as uint16_t,
    618 as libc::c_int as uint16_t,
    619 as libc::c_int as uint16_t,
    636 as libc::c_int as uint16_t,
    640 as libc::c_int as uint16_t,
    641 as libc::c_int as uint16_t,
    637 as libc::c_int as uint16_t,
    638 as libc::c_int as uint16_t,
    639 as libc::c_int as uint16_t,
    805 as libc::c_int as uint16_t,
    806 as libc::c_int as uint16_t,
    184 as libc::c_int as uint16_t,
    405 as libc::c_int as uint16_t,
    389 as libc::c_int as uint16_t,
    504 as libc::c_int as uint16_t,
    104 as libc::c_int as uint16_t,
    29 as libc::c_int as uint16_t,
    31 as libc::c_int as uint16_t,
    45 as libc::c_int as uint16_t,
    30 as libc::c_int as uint16_t,
    377 as libc::c_int as uint16_t,
    67 as libc::c_int as uint16_t,
    66 as libc::c_int as uint16_t,
    42 as libc::c_int as uint16_t,
    32 as libc::c_int as uint16_t,
    41 as libc::c_int as uint16_t,
    64 as libc::c_int as uint16_t,
    70 as libc::c_int as uint16_t,
    115 as libc::c_int as uint16_t,
    117 as libc::c_int as uint16_t,
    143 as libc::c_int as uint16_t,
    721 as libc::c_int as uint16_t,
    722 as libc::c_int as uint16_t,
    728 as libc::c_int as uint16_t,
    717 as libc::c_int as uint16_t,
    718 as libc::c_int as uint16_t,
    704 as libc::c_int as uint16_t,
    705 as libc::c_int as uint16_t,
    709 as libc::c_int as uint16_t,
    708 as libc::c_int as uint16_t,
    714 as libc::c_int as uint16_t,
    723 as libc::c_int as uint16_t,
    729 as libc::c_int as uint16_t,
    730 as libc::c_int as uint16_t,
    719 as libc::c_int as uint16_t,
    720 as libc::c_int as uint16_t,
    724 as libc::c_int as uint16_t,
    725 as libc::c_int as uint16_t,
    726 as libc::c_int as uint16_t,
    727 as libc::c_int as uint16_t,
    706 as libc::c_int as uint16_t,
    707 as libc::c_int as uint16_t,
    710 as libc::c_int as uint16_t,
    711 as libc::c_int as uint16_t,
    712 as libc::c_int as uint16_t,
    713 as libc::c_int as uint16_t,
    715 as libc::c_int as uint16_t,
    716 as libc::c_int as uint16_t,
    731 as libc::c_int as uint16_t,
    732 as libc::c_int as uint16_t,
    733 as libc::c_int as uint16_t,
    734 as libc::c_int as uint16_t,
    982 as libc::c_int as uint16_t,
    981 as libc::c_int as uint16_t,
    991 as libc::c_int as uint16_t,
    992 as libc::c_int as uint16_t,
    624 as libc::c_int as uint16_t,
    625 as libc::c_int as uint16_t,
    626 as libc::c_int as uint16_t,
    627 as libc::c_int as uint16_t,
    628 as libc::c_int as uint16_t,
    629 as libc::c_int as uint16_t,
    630 as libc::c_int as uint16_t,
    642 as libc::c_int as uint16_t,
    735 as libc::c_int as uint16_t,
    736 as libc::c_int as uint16_t,
    737 as libc::c_int as uint16_t,
    738 as libc::c_int as uint16_t,
    739 as libc::c_int as uint16_t,
    740 as libc::c_int as uint16_t,
    741 as libc::c_int as uint16_t,
    742 as libc::c_int as uint16_t,
    743 as libc::c_int as uint16_t,
    744 as libc::c_int as uint16_t,
    745 as libc::c_int as uint16_t,
    804 as libc::c_int as uint16_t,
    773 as libc::c_int as uint16_t,
    807 as libc::c_int as uint16_t,
    808 as libc::c_int as uint16_t,
    809 as libc::c_int as uint16_t,
    810 as libc::c_int as uint16_t,
    811 as libc::c_int as uint16_t,
    812 as libc::c_int as uint16_t,
    813 as libc::c_int as uint16_t,
    815 as libc::c_int as uint16_t,
    816 as libc::c_int as uint16_t,
    817 as libc::c_int as uint16_t,
    818 as libc::c_int as uint16_t,
    1 as libc::c_int as uint16_t,
    185 as libc::c_int as uint16_t,
    127 as libc::c_int as uint16_t,
    505 as libc::c_int as uint16_t,
    506 as libc::c_int as uint16_t,
    119 as libc::c_int as uint16_t,
    937 as libc::c_int as uint16_t,
    938 as libc::c_int as uint16_t,
    939 as libc::c_int as uint16_t,
    940 as libc::c_int as uint16_t,
    942 as libc::c_int as uint16_t,
    943 as libc::c_int as uint16_t,
    944 as libc::c_int as uint16_t,
    945 as libc::c_int as uint16_t,
    631 as libc::c_int as uint16_t,
    632 as libc::c_int as uint16_t,
    633 as libc::c_int as uint16_t,
    634 as libc::c_int as uint16_t,
    635 as libc::c_int as uint16_t,
    436 as libc::c_int as uint16_t,
    820 as libc::c_int as uint16_t,
    819 as libc::c_int as uint16_t,
    845 as libc::c_int as uint16_t,
    846 as libc::c_int as uint16_t,
    847 as libc::c_int as uint16_t,
    848 as libc::c_int as uint16_t,
    821 as libc::c_int as uint16_t,
    822 as libc::c_int as uint16_t,
    823 as libc::c_int as uint16_t,
    824 as libc::c_int as uint16_t,
    825 as libc::c_int as uint16_t,
    826 as libc::c_int as uint16_t,
    827 as libc::c_int as uint16_t,
    828 as libc::c_int as uint16_t,
    829 as libc::c_int as uint16_t,
    830 as libc::c_int as uint16_t,
    831 as libc::c_int as uint16_t,
    832 as libc::c_int as uint16_t,
    833 as libc::c_int as uint16_t,
    834 as libc::c_int as uint16_t,
    835 as libc::c_int as uint16_t,
    836 as libc::c_int as uint16_t,
    837 as libc::c_int as uint16_t,
    838 as libc::c_int as uint16_t,
    839 as libc::c_int as uint16_t,
    840 as libc::c_int as uint16_t,
    841 as libc::c_int as uint16_t,
    842 as libc::c_int as uint16_t,
    843 as libc::c_int as uint16_t,
    844 as libc::c_int as uint16_t,
    2 as libc::c_int as uint16_t,
    431 as libc::c_int as uint16_t,
    432 as libc::c_int as uint16_t,
    433 as libc::c_int as uint16_t,
    116 as libc::c_int as uint16_t,
    113 as libc::c_int as uint16_t,
    406 as libc::c_int as uint16_t,
    407 as libc::c_int as uint16_t,
    408 as libc::c_int as uint16_t,
    416 as libc::c_int as uint16_t,
    791 as libc::c_int as uint16_t,
    792 as libc::c_int as uint16_t,
    920 as libc::c_int as uint16_t,
    258 as libc::c_int as uint16_t,
    175 as libc::c_int as uint16_t,
    259 as libc::c_int as uint16_t,
    128 as libc::c_int as uint16_t,
    260 as libc::c_int as uint16_t,
    261 as libc::c_int as uint16_t,
    262 as libc::c_int as uint16_t,
    263 as libc::c_int as uint16_t,
    264 as libc::c_int as uint16_t,
    265 as libc::c_int as uint16_t,
    266 as libc::c_int as uint16_t,
    267 as libc::c_int as uint16_t,
    268 as libc::c_int as uint16_t,
    662 as libc::c_int as uint16_t,
    176 as libc::c_int as uint16_t,
    507 as libc::c_int as uint16_t,
    508 as libc::c_int as uint16_t,
    57 as libc::c_int as uint16_t,
    754 as libc::c_int as uint16_t,
    766 as libc::c_int as uint16_t,
    757 as libc::c_int as uint16_t,
    755 as libc::c_int as uint16_t,
    767 as libc::c_int as uint16_t,
    758 as libc::c_int as uint16_t,
    756 as libc::c_int as uint16_t,
    768 as libc::c_int as uint16_t,
    759 as libc::c_int as uint16_t,
    437 as libc::c_int as uint16_t,
    776 as libc::c_int as uint16_t,
    777 as libc::c_int as uint16_t,
    779 as libc::c_int as uint16_t,
    778 as libc::c_int as uint16_t,
    852 as libc::c_int as uint16_t,
    853 as libc::c_int as uint16_t,
    850 as libc::c_int as uint16_t,
    851 as libc::c_int as uint16_t,
    849 as libc::c_int as uint16_t,
    854 as libc::c_int as uint16_t,
    186 as libc::c_int as uint16_t,
    27 as libc::c_int as uint16_t,
    187 as libc::c_int as uint16_t,
    20 as libc::c_int as uint16_t,
    47 as libc::c_int as uint16_t,
    3 as libc::c_int as uint16_t,
    257 as libc::c_int as uint16_t,
    4 as libc::c_int as uint16_t,
    797 as libc::c_int as uint16_t,
    163 as libc::c_int as uint16_t,
    798 as libc::c_int as uint16_t,
    799 as libc::c_int as uint16_t,
    800 as libc::c_int as uint16_t,
    801 as libc::c_int as uint16_t,
    37 as libc::c_int as uint16_t,
    5 as libc::c_int as uint16_t,
    44 as libc::c_int as uint16_t,
    120 as libc::c_int as uint16_t,
    643 as libc::c_int as uint16_t,
    680 as libc::c_int as uint16_t,
    684 as libc::c_int as uint16_t,
    685 as libc::c_int as uint16_t,
    686 as libc::c_int as uint16_t,
    687 as libc::c_int as uint16_t,
    688 as libc::c_int as uint16_t,
    689 as libc::c_int as uint16_t,
    690 as libc::c_int as uint16_t,
    691 as libc::c_int as uint16_t,
    692 as libc::c_int as uint16_t,
    693 as libc::c_int as uint16_t,
    694 as libc::c_int as uint16_t,
    695 as libc::c_int as uint16_t,
    696 as libc::c_int as uint16_t,
    697 as libc::c_int as uint16_t,
    698 as libc::c_int as uint16_t,
    699 as libc::c_int as uint16_t,
    700 as libc::c_int as uint16_t,
    701 as libc::c_int as uint16_t,
    702 as libc::c_int as uint16_t,
    703 as libc::c_int as uint16_t,
    409 as libc::c_int as uint16_t,
    410 as libc::c_int as uint16_t,
    411 as libc::c_int as uint16_t,
    412 as libc::c_int as uint16_t,
    413 as libc::c_int as uint16_t,
    414 as libc::c_int as uint16_t,
    415 as libc::c_int as uint16_t,
    793 as libc::c_int as uint16_t,
    794 as libc::c_int as uint16_t,
    795 as libc::c_int as uint16_t,
    796 as libc::c_int as uint16_t,
    269 as libc::c_int as uint16_t,
    270 as libc::c_int as uint16_t,
    271 as libc::c_int as uint16_t,
    272 as libc::c_int as uint16_t,
    273 as libc::c_int as uint16_t,
    274 as libc::c_int as uint16_t,
    275 as libc::c_int as uint16_t,
    276 as libc::c_int as uint16_t,
    277 as libc::c_int as uint16_t,
    278 as libc::c_int as uint16_t,
    279 as libc::c_int as uint16_t,
    280 as libc::c_int as uint16_t,
    281 as libc::c_int as uint16_t,
    282 as libc::c_int as uint16_t,
    283 as libc::c_int as uint16_t,
    284 as libc::c_int as uint16_t,
    177 as libc::c_int as uint16_t,
    285 as libc::c_int as uint16_t,
    286 as libc::c_int as uint16_t,
    287 as libc::c_int as uint16_t,
    288 as libc::c_int as uint16_t,
    289 as libc::c_int as uint16_t,
    290 as libc::c_int as uint16_t,
    291 as libc::c_int as uint16_t,
    292 as libc::c_int as uint16_t,
    397 as libc::c_int as uint16_t,
    398 as libc::c_int as uint16_t,
    663 as libc::c_int as uint16_t,
    164 as libc::c_int as uint16_t,
    165 as libc::c_int as uint16_t,
    293 as libc::c_int as uint16_t,
    129 as libc::c_int as uint16_t,
    130 as libc::c_int as uint16_t,
    131 as libc::c_int as uint16_t,
    132 as libc::c_int as uint16_t,
    294 as libc::c_int as uint16_t,
    295 as libc::c_int as uint16_t,
    296 as libc::c_int as uint16_t,
    133 as libc::c_int as uint16_t,
    180 as libc::c_int as uint16_t,
    297 as libc::c_int as uint16_t,
    298 as libc::c_int as uint16_t,
    299 as libc::c_int as uint16_t,
    300 as libc::c_int as uint16_t,
    301 as libc::c_int as uint16_t,
    302 as libc::c_int as uint16_t,
    303 as libc::c_int as uint16_t,
    304 as libc::c_int as uint16_t,
    305 as libc::c_int as uint16_t,
    306 as libc::c_int as uint16_t,
    307 as libc::c_int as uint16_t,
    308 as libc::c_int as uint16_t,
    309 as libc::c_int as uint16_t,
    310 as libc::c_int as uint16_t,
    311 as libc::c_int as uint16_t,
    312 as libc::c_int as uint16_t,
    784 as libc::c_int as uint16_t,
    313 as libc::c_int as uint16_t,
    314 as libc::c_int as uint16_t,
    323 as libc::c_int as uint16_t,
    324 as libc::c_int as uint16_t,
    325 as libc::c_int as uint16_t,
    326 as libc::c_int as uint16_t,
    327 as libc::c_int as uint16_t,
    328 as libc::c_int as uint16_t,
    329 as libc::c_int as uint16_t,
    330 as libc::c_int as uint16_t,
    331 as libc::c_int as uint16_t,
    332 as libc::c_int as uint16_t,
    333 as libc::c_int as uint16_t,
    334 as libc::c_int as uint16_t,
    335 as libc::c_int as uint16_t,
    336 as libc::c_int as uint16_t,
    337 as libc::c_int as uint16_t,
    338 as libc::c_int as uint16_t,
    339 as libc::c_int as uint16_t,
    340 as libc::c_int as uint16_t,
    341 as libc::c_int as uint16_t,
    342 as libc::c_int as uint16_t,
    343 as libc::c_int as uint16_t,
    344 as libc::c_int as uint16_t,
    345 as libc::c_int as uint16_t,
    346 as libc::c_int as uint16_t,
    347 as libc::c_int as uint16_t,
    858 as libc::c_int as uint16_t,
    348 as libc::c_int as uint16_t,
    349 as libc::c_int as uint16_t,
    351 as libc::c_int as uint16_t,
    352 as libc::c_int as uint16_t,
    353 as libc::c_int as uint16_t,
    354 as libc::c_int as uint16_t,
    355 as libc::c_int as uint16_t,
    356 as libc::c_int as uint16_t,
    357 as libc::c_int as uint16_t,
    358 as libc::c_int as uint16_t,
    399 as libc::c_int as uint16_t,
    359 as libc::c_int as uint16_t,
    360 as libc::c_int as uint16_t,
    361 as libc::c_int as uint16_t,
    362 as libc::c_int as uint16_t,
    664 as libc::c_int as uint16_t,
    665 as libc::c_int as uint16_t,
    667 as libc::c_int as uint16_t,
    178 as libc::c_int as uint16_t,
    179 as libc::c_int as uint16_t,
    363 as libc::c_int as uint16_t,
    364 as libc::c_int as uint16_t,
    785 as libc::c_int as uint16_t,
    780 as libc::c_int as uint16_t,
    781 as libc::c_int as uint16_t,
    993 as libc::c_int as uint16_t,
    970 as libc::c_int as uint16_t,
    58 as libc::c_int as uint16_t,
    59 as libc::c_int as uint16_t,
    438 as libc::c_int as uint16_t,
    439 as libc::c_int as uint16_t,
    440 as libc::c_int as uint16_t,
    441 as libc::c_int as uint16_t,
    108 as libc::c_int as uint16_t,
    112 as libc::c_int as uint16_t,
    782 as libc::c_int as uint16_t,
    783 as libc::c_int as uint16_t,
    6 as libc::c_int as uint16_t,
    7 as libc::c_int as uint16_t,
    396 as libc::c_int as uint16_t,
    8 as libc::c_int as uint16_t,
    65 as libc::c_int as uint16_t,
    644 as libc::c_int as uint16_t,
    919 as libc::c_int as uint16_t,
    911 as libc::c_int as uint16_t,
    935 as libc::c_int as uint16_t,
    912 as libc::c_int as uint16_t,
    668 as libc::c_int as uint16_t,
    669 as libc::c_int as uint16_t,
    670 as libc::c_int as uint16_t,
    671 as libc::c_int as uint16_t,
    28 as libc::c_int as uint16_t,
    9 as libc::c_int as uint16_t,
    10 as libc::c_int as uint16_t,
    168 as libc::c_int as uint16_t,
    169 as libc::c_int as uint16_t,
    170 as libc::c_int as uint16_t,
    68 as libc::c_int as uint16_t,
    69 as libc::c_int as uint16_t,
    161 as libc::c_int as uint16_t,
    162 as libc::c_int as uint16_t,
    21 as libc::c_int as uint16_t,
    22 as libc::c_int as uint16_t,
    23 as libc::c_int as uint16_t,
    24 as libc::c_int as uint16_t,
    25 as libc::c_int as uint16_t,
    26 as libc::c_int as uint16_t,
    48 as libc::c_int as uint16_t,
    49 as libc::c_int as uint16_t,
    50 as libc::c_int as uint16_t,
    51 as libc::c_int as uint16_t,
    52 as libc::c_int as uint16_t,
    53 as libc::c_int as uint16_t,
    54 as libc::c_int as uint16_t,
    55 as libc::c_int as uint16_t,
    56 as libc::c_int as uint16_t,
    172 as libc::c_int as uint16_t,
    167 as libc::c_int as uint16_t,
    188 as libc::c_int as uint16_t,
    156 as libc::c_int as uint16_t,
    157 as libc::c_int as uint16_t,
    681 as libc::c_int as uint16_t,
    682 as libc::c_int as uint16_t,
    683 as libc::c_int as uint16_t,
    417 as libc::c_int as uint16_t,
    856 as libc::c_int as uint16_t,
    998 as libc::c_int as uint16_t,
    390 as libc::c_int as uint16_t,
    91 as libc::c_int as uint16_t,
    315 as libc::c_int as uint16_t,
    316 as libc::c_int as uint16_t,
    317 as libc::c_int as uint16_t,
    318 as libc::c_int as uint16_t,
    319 as libc::c_int as uint16_t,
    320 as libc::c_int as uint16_t,
    321 as libc::c_int as uint16_t,
    322 as libc::c_int as uint16_t,
    365 as libc::c_int as uint16_t,
    366 as libc::c_int as uint16_t,
    367 as libc::c_int as uint16_t,
    368 as libc::c_int as uint16_t,
    369 as libc::c_int as uint16_t,
    370 as libc::c_int as uint16_t,
    371 as libc::c_int as uint16_t,
    372 as libc::c_int as uint16_t,
    373 as libc::c_int as uint16_t,
    374 as libc::c_int as uint16_t,
    375 as libc::c_int as uint16_t,
    921 as libc::c_int as uint16_t,
    922 as libc::c_int as uint16_t,
    923 as libc::c_int as uint16_t,
    924 as libc::c_int as uint16_t,
    925 as libc::c_int as uint16_t,
    926 as libc::c_int as uint16_t,
    927 as libc::c_int as uint16_t,
    928 as libc::c_int as uint16_t,
    929 as libc::c_int as uint16_t,
    930 as libc::c_int as uint16_t,
    931 as libc::c_int as uint16_t,
    932 as libc::c_int as uint16_t,
    933 as libc::c_int as uint16_t,
    934 as libc::c_int as uint16_t,
    936 as libc::c_int as uint16_t,
    941 as libc::c_int as uint16_t,
    418 as libc::c_int as uint16_t,
    419 as libc::c_int as uint16_t,
    420 as libc::c_int as uint16_t,
    421 as libc::c_int as uint16_t,
    788 as libc::c_int as uint16_t,
    895 as libc::c_int as uint16_t,
    896 as libc::c_int as uint16_t,
    897 as libc::c_int as uint16_t,
    422 as libc::c_int as uint16_t,
    423 as libc::c_int as uint16_t,
    424 as libc::c_int as uint16_t,
    425 as libc::c_int as uint16_t,
    789 as libc::c_int as uint16_t,
    898 as libc::c_int as uint16_t,
    899 as libc::c_int as uint16_t,
    900 as libc::c_int as uint16_t,
    426 as libc::c_int as uint16_t,
    427 as libc::c_int as uint16_t,
    428 as libc::c_int as uint16_t,
    429 as libc::c_int as uint16_t,
    790 as libc::c_int as uint16_t,
    901 as libc::c_int as uint16_t,
    902 as libc::c_int as uint16_t,
    903 as libc::c_int as uint16_t,
    672 as libc::c_int as uint16_t,
    673 as libc::c_int as uint16_t,
    674 as libc::c_int as uint16_t,
    675 as libc::c_int as uint16_t,
    978 as libc::c_int as uint16_t,
    962 as libc::c_int as uint16_t,
    965 as libc::c_int as uint16_t,
    966 as libc::c_int as uint16_t,
    967 as libc::c_int as uint16_t,
    968 as libc::c_int as uint16_t,
    979 as libc::c_int as uint16_t,
    980 as libc::c_int as uint16_t,
    802 as libc::c_int as uint16_t,
    803 as libc::c_int as uint16_t,
    994 as libc::c_int as uint16_t,
    995 as libc::c_int as uint16_t,
    996 as libc::c_int as uint16_t,
    988 as libc::c_int as uint16_t,
    989 as libc::c_int as uint16_t,
    990 as libc::c_int as uint16_t,
    71 as libc::c_int as uint16_t,
    72 as libc::c_int as uint16_t,
    73 as libc::c_int as uint16_t,
    74 as libc::c_int as uint16_t,
    75 as libc::c_int as uint16_t,
    76 as libc::c_int as uint16_t,
    77 as libc::c_int as uint16_t,
    78 as libc::c_int as uint16_t,
    79 as libc::c_int as uint16_t,
    139 as libc::c_int as uint16_t,
    458 as libc::c_int as uint16_t,
    459 as libc::c_int as uint16_t,
    460 as libc::c_int as uint16_t,
    461 as libc::c_int as uint16_t,
    462 as libc::c_int as uint16_t,
    463 as libc::c_int as uint16_t,
    464 as libc::c_int as uint16_t,
    465 as libc::c_int as uint16_t,
    466 as libc::c_int as uint16_t,
    467 as libc::c_int as uint16_t,
    468 as libc::c_int as uint16_t,
    469 as libc::c_int as uint16_t,
    470 as libc::c_int as uint16_t,
    471 as libc::c_int as uint16_t,
    472 as libc::c_int as uint16_t,
    473 as libc::c_int as uint16_t,
    474 as libc::c_int as uint16_t,
    475 as libc::c_int as uint16_t,
    476 as libc::c_int as uint16_t,
    477 as libc::c_int as uint16_t,
    391 as libc::c_int as uint16_t,
    478 as libc::c_int as uint16_t,
    479 as libc::c_int as uint16_t,
    480 as libc::c_int as uint16_t,
    481 as libc::c_int as uint16_t,
    482 as libc::c_int as uint16_t,
    483 as libc::c_int as uint16_t,
    484 as libc::c_int as uint16_t,
    485 as libc::c_int as uint16_t,
    486 as libc::c_int as uint16_t,
    487 as libc::c_int as uint16_t,
    488 as libc::c_int as uint16_t,
    489 as libc::c_int as uint16_t,
    490 as libc::c_int as uint16_t,
    491 as libc::c_int as uint16_t,
    492 as libc::c_int as uint16_t,
    493 as libc::c_int as uint16_t,
    494 as libc::c_int as uint16_t,
    495 as libc::c_int as uint16_t,
    496 as libc::c_int as uint16_t,
    497 as libc::c_int as uint16_t,
    498 as libc::c_int as uint16_t,
    499 as libc::c_int as uint16_t,
    500 as libc::c_int as uint16_t,
    501 as libc::c_int as uint16_t,
    502 as libc::c_int as uint16_t,
    442 as libc::c_int as uint16_t,
    443 as libc::c_int as uint16_t,
    444 as libc::c_int as uint16_t,
    445 as libc::c_int as uint16_t,
    446 as libc::c_int as uint16_t,
    447 as libc::c_int as uint16_t,
    448 as libc::c_int as uint16_t,
    449 as libc::c_int as uint16_t,
    392 as libc::c_int as uint16_t,
    450 as libc::c_int as uint16_t,
    451 as libc::c_int as uint16_t,
    452 as libc::c_int as uint16_t,
    453 as libc::c_int as uint16_t,
    454 as libc::c_int as uint16_t,
    455 as libc::c_int as uint16_t,
    456 as libc::c_int as uint16_t,
    457 as libc::c_int as uint16_t,
    189 as libc::c_int as uint16_t,
    190 as libc::c_int as uint16_t,
    191 as libc::c_int as uint16_t,
    192 as libc::c_int as uint16_t,
    193 as libc::c_int as uint16_t,
    194 as libc::c_int as uint16_t,
    195 as libc::c_int as uint16_t,
    158 as libc::c_int as uint16_t,
    159 as libc::c_int as uint16_t,
    160 as libc::c_int as uint16_t,
    144 as libc::c_int as uint16_t,
    145 as libc::c_int as uint16_t,
    146 as libc::c_int as uint16_t,
    147 as libc::c_int as uint16_t,
    148 as libc::c_int as uint16_t,
    149 as libc::c_int as uint16_t,
    171 as libc::c_int as uint16_t,
    134 as libc::c_int as uint16_t,
    135 as libc::c_int as uint16_t,
    136 as libc::c_int as uint16_t,
    137 as libc::c_int as uint16_t,
    138 as libc::c_int as uint16_t,
    648 as libc::c_int as uint16_t,
    649 as libc::c_int as uint16_t,
    751 as libc::c_int as uint16_t,
    752 as libc::c_int as uint16_t,
    753 as libc::c_int as uint16_t,
    907 as libc::c_int as uint16_t,
    908 as libc::c_int as uint16_t,
    909 as libc::c_int as uint16_t,
    196 as libc::c_int as uint16_t,
    197 as libc::c_int as uint16_t,
    198 as libc::c_int as uint16_t,
    199 as libc::c_int as uint16_t,
    200 as libc::c_int as uint16_t,
    201 as libc::c_int as uint16_t,
    202 as libc::c_int as uint16_t,
    203 as libc::c_int as uint16_t,
    204 as libc::c_int as uint16_t,
    205 as libc::c_int as uint16_t,
    206 as libc::c_int as uint16_t,
    207 as libc::c_int as uint16_t,
    208 as libc::c_int as uint16_t,
    209 as libc::c_int as uint16_t,
    210 as libc::c_int as uint16_t,
    211 as libc::c_int as uint16_t,
    786 as libc::c_int as uint16_t,
    787 as libc::c_int as uint16_t,
    212 as libc::c_int as uint16_t,
    213 as libc::c_int as uint16_t,
    214 as libc::c_int as uint16_t,
    215 as libc::c_int as uint16_t,
    216 as libc::c_int as uint16_t,
    217 as libc::c_int as uint16_t,
    218 as libc::c_int as uint16_t,
    219 as libc::c_int as uint16_t,
    220 as libc::c_int as uint16_t,
    221 as libc::c_int as uint16_t,
    222 as libc::c_int as uint16_t,
    223 as libc::c_int as uint16_t,
    224 as libc::c_int as uint16_t,
    225 as libc::c_int as uint16_t,
    226 as libc::c_int as uint16_t,
    227 as libc::c_int as uint16_t,
    228 as libc::c_int as uint16_t,
    229 as libc::c_int as uint16_t,
    230 as libc::c_int as uint16_t,
    231 as libc::c_int as uint16_t,
    232 as libc::c_int as uint16_t,
    233 as libc::c_int as uint16_t,
    234 as libc::c_int as uint16_t,
    235 as libc::c_int as uint16_t,
    236 as libc::c_int as uint16_t,
    237 as libc::c_int as uint16_t,
    238 as libc::c_int as uint16_t,
    239 as libc::c_int as uint16_t,
    240 as libc::c_int as uint16_t,
    241 as libc::c_int as uint16_t,
    242 as libc::c_int as uint16_t,
    243 as libc::c_int as uint16_t,
    244 as libc::c_int as uint16_t,
    245 as libc::c_int as uint16_t,
    246 as libc::c_int as uint16_t,
    247 as libc::c_int as uint16_t,
    125 as libc::c_int as uint16_t,
    893 as libc::c_int as uint16_t,
    248 as libc::c_int as uint16_t,
    249 as libc::c_int as uint16_t,
    250 as libc::c_int as uint16_t,
    251 as libc::c_int as uint16_t,
    252 as libc::c_int as uint16_t,
    253 as libc::c_int as uint16_t,
    254 as libc::c_int as uint16_t,
    255 as libc::c_int as uint16_t,
    256 as libc::c_int as uint16_t,
    150 as libc::c_int as uint16_t,
    151 as libc::c_int as uint16_t,
    152 as libc::c_int as uint16_t,
    153 as libc::c_int as uint16_t,
    154 as libc::c_int as uint16_t,
    155 as libc::c_int as uint16_t,
    975 as libc::c_int as uint16_t,
    34 as libc::c_int as uint16_t,
];
#[inline]
unsafe extern "C" fn lh_ASN1_OBJECT_call_hash_func(
    mut func: lhash_hash_func,
    mut a: *const libc::c_void,
) -> uint32_t {
    return (::core::mem::transmute::<lhash_hash_func, lhash_ASN1_OBJECT_hash_func>(func))
        .expect("non-null function pointer")(a as *const ASN1_OBJECT);
}
#[inline]
unsafe extern "C" fn lh_ASN1_OBJECT_retrieve(
    mut lh: *const lhash_st_ASN1_OBJECT,
    mut data: *const ASN1_OBJECT,
) -> *mut ASN1_OBJECT {
    return OPENSSL_lh_retrieve(
        lh as *const _LHASH,
        data as *const libc::c_void,
        Some(
            lh_ASN1_OBJECT_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_ASN1_OBJECT_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *mut ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn lh_ASN1_OBJECT_new(
    mut hash: lhash_ASN1_OBJECT_hash_func,
    mut comp: lhash_ASN1_OBJECT_cmp_func,
) -> *mut lhash_st_ASN1_OBJECT {
    return OPENSSL_lh_new(
        ::core::mem::transmute::<lhash_ASN1_OBJECT_hash_func, lhash_hash_func>(hash),
        ::core::mem::transmute::<lhash_ASN1_OBJECT_cmp_func, lhash_cmp_func>(comp),
    ) as *mut lhash_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn lh_ASN1_OBJECT_insert(
    mut lh: *mut lhash_st_ASN1_OBJECT,
    mut old_data: *mut *mut ASN1_OBJECT,
    mut data: *mut ASN1_OBJECT,
) -> libc::c_int {
    let mut old_data_void: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut ret: libc::c_int = OPENSSL_lh_insert(
        lh as *mut _LHASH,
        &mut old_data_void,
        data as *mut libc::c_void,
        Some(
            lh_ASN1_OBJECT_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_ASN1_OBJECT_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    *old_data = old_data_void as *mut ASN1_OBJECT;
    return ret;
}
#[inline]
unsafe extern "C" fn lh_ASN1_OBJECT_call_cmp_func(
    mut func: lhash_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    return (::core::mem::transmute::<lhash_cmp_func, lhash_ASN1_OBJECT_cmp_func>(func))
        .expect(
            "non-null function pointer",
        )(a as *const ASN1_OBJECT, b as *const ASN1_OBJECT);
}
static mut global_added_lock: CRYPTO_STATIC_MUTEX = {
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
static mut global_added_by_data: *mut lhash_st_ASN1_OBJECT = 0
    as *const lhash_st_ASN1_OBJECT as *mut lhash_st_ASN1_OBJECT;
static mut global_added_by_nid: *mut lhash_st_ASN1_OBJECT = 0
    as *const lhash_st_ASN1_OBJECT as *mut lhash_st_ASN1_OBJECT;
static mut global_added_by_short_name: *mut lhash_st_ASN1_OBJECT = 0
    as *const lhash_st_ASN1_OBJECT as *mut lhash_st_ASN1_OBJECT;
static mut global_added_by_long_name: *mut lhash_st_ASN1_OBJECT = 0
    as *const lhash_st_ASN1_OBJECT as *mut lhash_st_ASN1_OBJECT;
static mut global_next_nid_lock: CRYPTO_STATIC_MUTEX = {
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
static mut global_next_nid: libc::c_uint = 999 as libc::c_int as libc::c_uint;
unsafe extern "C" fn obj_next_nid() -> libc::c_int {
    let mut ret: libc::c_int = 0;
    CRYPTO_STATIC_MUTEX_lock_write(&mut global_next_nid_lock);
    let fresh0 = global_next_nid;
    global_next_nid = global_next_nid.wrapping_add(1);
    ret = fresh0 as libc::c_int;
    CRYPTO_STATIC_MUTEX_unlock_write(&mut global_next_nid_lock);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_dup(mut o: *const ASN1_OBJECT) -> *mut ASN1_OBJECT {
    let mut current_block: u64;
    let mut r: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut sn: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ln: *mut libc::c_char = 0 as *mut libc::c_char;
    if o.is_null() {
        return 0 as *mut ASN1_OBJECT;
    }
    if (*o).flags & 0x1 as libc::c_int == 0 {
        return o as *mut ASN1_OBJECT;
    }
    r = ASN1_OBJECT_new();
    if r.is_null() {
        ERR_put_error(
            8 as libc::c_int,
            0 as libc::c_int,
            12 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/obj/obj.c\0" as *const u8
                as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OBJECT;
    }
    (*r).sn = 0 as *const libc::c_char;
    (*r).ln = (*r).sn;
    (*r)
        .data = OPENSSL_memdup((*o).data as *const libc::c_void, (*o).length as size_t)
        as *const libc::c_uchar;
    if !((*o).length != 0 as libc::c_int && ((*r).data).is_null()) {
        (*r).length = (*o).length;
        (*r).nid = (*o).nid;
        if !((*o).ln).is_null() {
            ln = OPENSSL_strdup((*o).ln);
            if ln.is_null() {
                current_block = 15728106621058604838;
            } else {
                current_block = 9606288038608642794;
            }
        } else {
            current_block = 9606288038608642794;
        }
        match current_block {
            15728106621058604838 => {}
            _ => {
                if !((*o).sn).is_null() {
                    sn = OPENSSL_strdup((*o).sn);
                    if sn.is_null() {
                        current_block = 15728106621058604838;
                    } else {
                        current_block = 6057473163062296781;
                    }
                } else {
                    current_block = 6057473163062296781;
                }
                match current_block {
                    15728106621058604838 => {}
                    _ => {
                        (*r).sn = sn;
                        (*r).ln = ln;
                        (*r)
                            .flags = (*o).flags
                            | (0x1 as libc::c_int | 0x4 as libc::c_int
                                | 0x8 as libc::c_int);
                        return r;
                    }
                }
            }
        }
    }
    OPENSSL_free(ln as *mut libc::c_void);
    OPENSSL_free(sn as *mut libc::c_void);
    OPENSSL_free(data as *mut libc::c_void);
    OPENSSL_free(r as *mut libc::c_void);
    return 0 as *mut ASN1_OBJECT;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_cmp(
    mut a: *const ASN1_OBJECT,
    mut b: *const ASN1_OBJECT,
) -> libc::c_int {
    if (*a).length < (*b).length {
        return -(1 as libc::c_int)
    } else if (*a).length > (*b).length {
        return 1 as libc::c_int
    }
    return OPENSSL_memcmp(
        (*a).data as *const libc::c_void,
        (*b).data as *const libc::c_void,
        (*a).length as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_get0_data(mut obj: *const ASN1_OBJECT) -> *const uint8_t {
    if obj.is_null() {
        return 0 as *const uint8_t;
    }
    return (*obj).data;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_length(mut obj: *const ASN1_OBJECT) -> size_t {
    if obj.is_null() || (*obj).length < 0 as libc::c_int {
        return 0 as libc::c_int as size_t;
    }
    return (*obj).length as size_t;
}
unsafe extern "C" fn get_builtin_object(mut nid: libc::c_int) -> *const ASN1_OBJECT {
    if !(nid > 0 as libc::c_int && nid < 999 as libc::c_int) {
        abort();
    }
    return &*kObjects.as_ptr().offset((nid - 1 as libc::c_int) as isize)
        as *const ASN1_OBJECT;
}
unsafe extern "C" fn obj_cmp(
    mut key: *const libc::c_void,
    mut element: *const libc::c_void,
) -> libc::c_int {
    let mut nid: uint16_t = *(element as *const uint16_t);
    return OBJ_cmp(key as *const ASN1_OBJECT, get_builtin_object(nid as libc::c_int));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_obj2nid(mut obj: *const ASN1_OBJECT) -> libc::c_int {
    if obj.is_null() {
        return 0 as libc::c_int;
    }
    if (*obj).nid != 0 as libc::c_int {
        return (*obj).nid;
    }
    CRYPTO_STATIC_MUTEX_lock_read(&mut global_added_lock);
    if !global_added_by_data.is_null() {
        let mut match_0: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        match_0 = lh_ASN1_OBJECT_retrieve(global_added_by_data, obj);
        if !match_0.is_null() {
            CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
            return (*match_0).nid;
        }
    }
    CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
    let mut nid_ptr: *const uint16_t = bsearch(
        obj as *const libc::c_void,
        kNIDsInOIDOrder.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[uint16_t; 902]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint16_t>() as libc::c_ulong),
        ::core::mem::size_of::<uint16_t>() as libc::c_ulong,
        Some(
            obj_cmp
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const uint16_t;
    if nid_ptr.is_null() {
        return 0 as libc::c_int;
    }
    return (*get_builtin_object(*nid_ptr as libc::c_int)).nid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_cbs2nid(mut cbs: *const CBS) -> libc::c_int {
    if CBS_len(cbs) > 2147483647 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut obj: ASN1_OBJECT = asn1_object_st {
        sn: 0 as *const libc::c_char,
        ln: 0 as *const libc::c_char,
        nid: 0,
        length: 0,
        data: 0 as *const libc::c_uchar,
        flags: 0,
    };
    OPENSSL_memset(
        &mut obj as *mut ASN1_OBJECT as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<ASN1_OBJECT>() as libc::c_ulong,
    );
    obj.data = CBS_data(cbs);
    obj.length = CBS_len(cbs) as libc::c_int;
    return OBJ_obj2nid(&mut obj);
}
unsafe extern "C" fn short_name_cmp(
    mut key: *const libc::c_void,
    mut element: *const libc::c_void,
) -> libc::c_int {
    let mut name: *const libc::c_char = key as *const libc::c_char;
    let mut nid: uint16_t = *(element as *const uint16_t);
    return strcmp(name, (*get_builtin_object(nid as libc::c_int)).sn);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_sn2nid(mut short_name: *const libc::c_char) -> libc::c_int {
    CRYPTO_STATIC_MUTEX_lock_read(&mut global_added_lock);
    if !global_added_by_short_name.is_null() {
        let mut match_0: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        let mut template: ASN1_OBJECT = asn1_object_st {
            sn: 0 as *const libc::c_char,
            ln: 0 as *const libc::c_char,
            nid: 0,
            length: 0,
            data: 0 as *const libc::c_uchar,
            flags: 0,
        };
        template.sn = short_name;
        match_0 = lh_ASN1_OBJECT_retrieve(global_added_by_short_name, &mut template);
        if !match_0.is_null() {
            CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
            return (*match_0).nid;
        }
    }
    CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
    let mut nid_ptr: *const uint16_t = bsearch(
        short_name as *const libc::c_void,
        kNIDsInShortNameOrder.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[uint16_t; 987]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint16_t>() as libc::c_ulong),
        ::core::mem::size_of::<uint16_t>() as libc::c_ulong,
        Some(
            short_name_cmp
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const uint16_t;
    if nid_ptr.is_null() {
        return 0 as libc::c_int;
    }
    return (*get_builtin_object(*nid_ptr as libc::c_int)).nid;
}
unsafe extern "C" fn long_name_cmp(
    mut key: *const libc::c_void,
    mut element: *const libc::c_void,
) -> libc::c_int {
    let mut name: *const libc::c_char = key as *const libc::c_char;
    let mut nid: uint16_t = *(element as *const uint16_t);
    return strcmp(name, (*get_builtin_object(nid as libc::c_int)).ln);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_ln2nid(mut long_name: *const libc::c_char) -> libc::c_int {
    CRYPTO_STATIC_MUTEX_lock_read(&mut global_added_lock);
    if !global_added_by_long_name.is_null() {
        let mut match_0: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        let mut template: ASN1_OBJECT = asn1_object_st {
            sn: 0 as *const libc::c_char,
            ln: 0 as *const libc::c_char,
            nid: 0,
            length: 0,
            data: 0 as *const libc::c_uchar,
            flags: 0,
        };
        template.ln = long_name;
        match_0 = lh_ASN1_OBJECT_retrieve(global_added_by_long_name, &mut template);
        if !match_0.is_null() {
            CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
            return (*match_0).nid;
        }
    }
    CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
    let mut nid_ptr: *const uint16_t = bsearch(
        long_name as *const libc::c_void,
        kNIDsInLongNameOrder.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[uint16_t; 987]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint16_t>() as libc::c_ulong),
        ::core::mem::size_of::<uint16_t>() as libc::c_ulong,
        Some(
            long_name_cmp
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const uint16_t;
    if nid_ptr.is_null() {
        return 0 as libc::c_int;
    }
    return (*get_builtin_object(*nid_ptr as libc::c_int)).nid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_txt2nid(mut s: *const libc::c_char) -> libc::c_int {
    let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut nid: libc::c_int = 0;
    obj = OBJ_txt2obj(s, 0 as libc::c_int);
    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    return nid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_nid2cbb(
    mut out: *mut CBB,
    mut nid: libc::c_int,
) -> libc::c_int {
    let mut obj: *const ASN1_OBJECT = OBJ_nid2obj(nid);
    let mut oid: CBB = cbb_st {
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
    if obj.is_null() || CBB_add_asn1(out, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(&mut oid, (*obj).data, (*obj).length as size_t) == 0
        || CBB_flush(out) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_get_undef() -> *const ASN1_OBJECT {
    static mut kUndef: ASN1_OBJECT = {
        let mut init = asn1_object_st {
            sn: b"UNDEF\0" as *const u8 as *const libc::c_char,
            ln: b"undefined\0" as *const u8 as *const libc::c_char,
            nid: 0 as libc::c_int,
            length: 0 as libc::c_int,
            data: 0 as *const libc::c_uchar,
            flags: 0 as libc::c_int,
        };
        init
    };
    return &kUndef;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_nid2obj(mut nid: libc::c_int) -> *mut ASN1_OBJECT {
    if nid == 0 as libc::c_int {
        return OBJ_get_undef() as *mut ASN1_OBJECT;
    }
    if nid > 0 as libc::c_int && nid < 999 as libc::c_int {
        let mut obj: *const ASN1_OBJECT = get_builtin_object(nid);
        if !(nid != 0 as libc::c_int && (*obj).nid == 0 as libc::c_int) {
            return obj as *mut ASN1_OBJECT;
        }
    } else {
        CRYPTO_STATIC_MUTEX_lock_read(&mut global_added_lock);
        if !global_added_by_nid.is_null() {
            let mut match_0: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
            let mut template: ASN1_OBJECT = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0,
                length: 0,
                data: 0 as *const libc::c_uchar,
                flags: 0,
            };
            template.nid = nid;
            match_0 = lh_ASN1_OBJECT_retrieve(global_added_by_nid, &mut template);
            if !match_0.is_null() {
                CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
                return match_0;
            }
        }
        CRYPTO_STATIC_MUTEX_unlock_read(&mut global_added_lock);
    }
    ERR_put_error(
        8 as libc::c_int,
        0 as libc::c_int,
        100 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/obj/obj.c\0" as *const u8
            as *const libc::c_char,
        381 as libc::c_int as libc::c_uint,
    );
    return 0 as *mut ASN1_OBJECT;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_nid2sn(mut nid: libc::c_int) -> *const libc::c_char {
    let mut obj: *const ASN1_OBJECT = OBJ_nid2obj(nid);
    if obj.is_null() {
        return 0 as *const libc::c_char;
    }
    return (*obj).sn;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_nid2ln(mut nid: libc::c_int) -> *const libc::c_char {
    let mut obj: *const ASN1_OBJECT = OBJ_nid2obj(nid);
    if obj.is_null() {
        return 0 as *const libc::c_char;
    }
    return (*obj).ln;
}
unsafe extern "C" fn create_object_with_text_oid(
    mut get_nid: Option::<unsafe extern "C" fn() -> libc::c_int>,
    mut oid: *const libc::c_char,
    mut short_name: *const libc::c_char,
    mut long_name: *const libc::c_char,
) -> *mut ASN1_OBJECT {
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
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
    if CBB_init(&mut cbb, 32 as libc::c_int as size_t) == 0
        || CBB_add_asn1_oid_from_text(&mut cbb, oid, strlen(oid)) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
    {
        ERR_put_error(
            8 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/obj/obj.c\0" as *const u8
                as *const libc::c_char,
            413 as libc::c_int as libc::c_uint,
        );
        CBB_cleanup(&mut cbb);
        return 0 as *mut ASN1_OBJECT;
    }
    let mut ret: *mut ASN1_OBJECT = ASN1_OBJECT_create(
        if get_nid.is_some() {
            get_nid.expect("non-null function pointer")()
        } else {
            0 as libc::c_int
        },
        buf,
        len,
        short_name,
        long_name,
    );
    OPENSSL_free(buf as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_txt2obj(
    mut s: *const libc::c_char,
    mut dont_search_names: libc::c_int,
) -> *mut ASN1_OBJECT {
    if dont_search_names == 0 {
        let mut nid: libc::c_int = OBJ_sn2nid(s);
        if nid == 0 as libc::c_int {
            nid = OBJ_ln2nid(s);
        }
        if nid != 0 as libc::c_int {
            return OBJ_nid2obj(nid);
        }
    }
    return create_object_with_text_oid(
        None,
        s,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
    );
}
unsafe extern "C" fn strlcpy_int(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dst_size: libc::c_int,
) -> libc::c_int {
    let mut ret: size_t = OPENSSL_strlcpy(
        dst,
        src,
        if dst_size < 0 as libc::c_int {
            0 as libc::c_int as size_t
        } else {
            dst_size as size_t
        },
    );
    if ret > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            8 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/obj/obj.c\0" as *const u8
                as *const libc::c_char,
            442 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return ret as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_obj2txt(
    mut out: *mut libc::c_char,
    mut out_len: libc::c_int,
    mut obj: *const ASN1_OBJECT,
    mut always_return_oid: libc::c_int,
) -> libc::c_int {
    if obj.is_null() || (*obj).length == 0 as libc::c_int {
        return strlcpy_int(out, b"\0" as *const u8 as *const libc::c_char, out_len);
    }
    if always_return_oid == 0 {
        let mut nid: libc::c_int = OBJ_obj2nid(obj);
        if nid != 0 as libc::c_int {
            let mut name: *const libc::c_char = OBJ_nid2ln(nid);
            if name.is_null() {
                name = OBJ_nid2sn(nid);
            }
            if !name.is_null() {
                return strlcpy_int(out, name, out_len);
            }
        }
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, (*obj).data, (*obj).length as size_t);
    let mut txt: *mut libc::c_char = CBS_asn1_oid_to_text(&mut cbs);
    if txt.is_null() {
        if out_len > 0 as libc::c_int {
            *out.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
        }
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = strlcpy_int(out, txt, out_len);
    OPENSSL_free(txt as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn hash_nid(mut obj: *const ASN1_OBJECT) -> uint32_t {
    return (*obj).nid as uint32_t;
}
unsafe extern "C" fn cmp_nid(
    mut a: *const ASN1_OBJECT,
    mut b: *const ASN1_OBJECT,
) -> libc::c_int {
    return (*a).nid - (*b).nid;
}
unsafe extern "C" fn hash_data(mut obj: *const ASN1_OBJECT) -> uint32_t {
    return OPENSSL_hash32((*obj).data as *const libc::c_void, (*obj).length as size_t);
}
unsafe extern "C" fn hash_short_name(mut obj: *const ASN1_OBJECT) -> uint32_t {
    return OPENSSL_strhash((*obj).sn);
}
unsafe extern "C" fn cmp_short_name(
    mut a: *const ASN1_OBJECT,
    mut b: *const ASN1_OBJECT,
) -> libc::c_int {
    return strcmp((*a).sn, (*b).sn);
}
unsafe extern "C" fn hash_long_name(mut obj: *const ASN1_OBJECT) -> uint32_t {
    return OPENSSL_strhash((*obj).ln);
}
unsafe extern "C" fn cmp_long_name(
    mut a: *const ASN1_OBJECT,
    mut b: *const ASN1_OBJECT,
) -> libc::c_int {
    return strcmp((*a).ln, (*b).ln);
}
unsafe extern "C" fn obj_add_object(mut obj: *mut ASN1_OBJECT) -> libc::c_int {
    let mut old_object: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    (*obj).flags &= !(0x1 as libc::c_int | 0x4 as libc::c_int | 0x8 as libc::c_int);
    CRYPTO_STATIC_MUTEX_lock_write(&mut global_added_lock);
    if global_added_by_nid.is_null() {
        global_added_by_nid = lh_ASN1_OBJECT_new(
            Some(hash_nid as unsafe extern "C" fn(*const ASN1_OBJECT) -> uint32_t),
            Some(
                cmp_nid
                    as unsafe extern "C" fn(
                        *const ASN1_OBJECT,
                        *const ASN1_OBJECT,
                    ) -> libc::c_int,
            ),
        );
    }
    if global_added_by_data.is_null() {
        global_added_by_data = lh_ASN1_OBJECT_new(
            Some(hash_data as unsafe extern "C" fn(*const ASN1_OBJECT) -> uint32_t),
            Some(
                OBJ_cmp
                    as unsafe extern "C" fn(
                        *const ASN1_OBJECT,
                        *const ASN1_OBJECT,
                    ) -> libc::c_int,
            ),
        );
    }
    if global_added_by_short_name.is_null() {
        global_added_by_short_name = lh_ASN1_OBJECT_new(
            Some(
                hash_short_name as unsafe extern "C" fn(*const ASN1_OBJECT) -> uint32_t,
            ),
            Some(
                cmp_short_name
                    as unsafe extern "C" fn(
                        *const ASN1_OBJECT,
                        *const ASN1_OBJECT,
                    ) -> libc::c_int,
            ),
        );
    }
    if global_added_by_long_name.is_null() {
        global_added_by_long_name = lh_ASN1_OBJECT_new(
            Some(hash_long_name as unsafe extern "C" fn(*const ASN1_OBJECT) -> uint32_t),
            Some(
                cmp_long_name
                    as unsafe extern "C" fn(
                        *const ASN1_OBJECT,
                        *const ASN1_OBJECT,
                    ) -> libc::c_int,
            ),
        );
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    if !(global_added_by_nid.is_null() || global_added_by_data.is_null()
        || global_added_by_short_name.is_null() || global_added_by_long_name.is_null())
    {
        old_object = 0 as *mut ASN1_OBJECT;
        ok = lh_ASN1_OBJECT_insert(global_added_by_nid, &mut old_object, obj);
        if (*obj).length != 0 as libc::c_int && !((*obj).data).is_null() {
            ok &= lh_ASN1_OBJECT_insert(global_added_by_data, &mut old_object, obj);
        }
        if !((*obj).sn).is_null() {
            ok
                &= lh_ASN1_OBJECT_insert(
                    global_added_by_short_name,
                    &mut old_object,
                    obj,
                );
        }
        if !((*obj).ln).is_null() {
            ok &= lh_ASN1_OBJECT_insert(global_added_by_long_name, &mut old_object, obj);
        }
    }
    CRYPTO_STATIC_MUTEX_unlock_write(&mut global_added_lock);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_create(
    mut oid: *const libc::c_char,
    mut short_name: *const libc::c_char,
    mut long_name: *const libc::c_char,
) -> libc::c_int {
    let mut op: *mut ASN1_OBJECT = create_object_with_text_oid(
        Some(obj_next_nid as unsafe extern "C" fn() -> libc::c_int),
        oid,
        short_name,
        long_name,
    );
    if op.is_null() || obj_add_object(op) == 0 {
        return 0 as libc::c_int;
    }
    return (*op).nid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_cleanup() {}
unsafe extern "C" fn run_static_initializers() {
    kObjects = [
        {
            let mut init = asn1_object_st {
                sn: b"rsadsi\0" as *const u8 as *const libc::c_char,
                ln: b"RSA Data Security, Inc.\0" as *const u8 as *const libc::c_char,
                nid: 1 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(0 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs\0" as *const u8 as *const libc::c_char,
                ln: b"RSA Data Security, Inc. PKCS\0" as *const u8
                    as *const libc::c_char,
                nid: 2 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MD2\0" as *const u8 as *const libc::c_char,
                ln: b"md2\0" as *const u8 as *const libc::c_char,
                nid: 3 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(13 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MD5\0" as *const u8 as *const libc::c_char,
                ln: b"md5\0" as *const u8 as *const libc::c_char,
                nid: 4 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(21 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC4\0" as *const u8 as *const libc::c_char,
                ln: b"rc4\0" as *const u8 as *const libc::c_char,
                nid: 5 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(29 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"rsaEncryption\0" as *const u8 as *const libc::c_char,
                ln: b"rsaEncryption\0" as *const u8 as *const libc::c_char,
                nid: 6 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(37 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-MD2\0" as *const u8 as *const libc::c_char,
                ln: b"md2WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 7 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(46 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-MD5\0" as *const u8 as *const libc::c_char,
                ln: b"md5WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 8 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(55 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-MD2-DES\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithMD2AndDES-CBC\0" as *const u8 as *const libc::c_char,
                nid: 9 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(64 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-MD5-DES\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithMD5AndDES-CBC\0" as *const u8 as *const libc::c_char,
                nid: 10 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(73 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X500\0" as *const u8 as *const libc::c_char,
                ln: b"directory services (X.500)\0" as *const u8 as *const libc::c_char,
                nid: 11 as libc::c_int,
                length: 1 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(82 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X509\0" as *const u8 as *const libc::c_char,
                ln: b"X509\0" as *const u8 as *const libc::c_char,
                nid: 12 as libc::c_int,
                length: 2 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(83 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CN\0" as *const u8 as *const libc::c_char,
                ln: b"commonName\0" as *const u8 as *const libc::c_char,
                nid: 13 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(85 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"C\0" as *const u8 as *const libc::c_char,
                ln: b"countryName\0" as *const u8 as *const libc::c_char,
                nid: 14 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(88 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"L\0" as *const u8 as *const libc::c_char,
                ln: b"localityName\0" as *const u8 as *const libc::c_char,
                nid: 15 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(91 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ST\0" as *const u8 as *const libc::c_char,
                ln: b"stateOrProvinceName\0" as *const u8 as *const libc::c_char,
                nid: 16 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(94 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"O\0" as *const u8 as *const libc::c_char,
                ln: b"organizationName\0" as *const u8 as *const libc::c_char,
                nid: 17 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(97 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"OU\0" as *const u8 as *const libc::c_char,
                ln: b"organizationalUnitName\0" as *const u8 as *const libc::c_char,
                nid: 18 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(100 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA\0" as *const u8 as *const libc::c_char,
                ln: b"rsa\0" as *const u8 as *const libc::c_char,
                nid: 19 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(103 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs7\0" as *const u8 as *const libc::c_char,
                nid: 20 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(107 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7-data\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs7-data\0" as *const u8 as *const libc::c_char,
                nid: 21 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(115 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7-signedData\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs7-signedData\0" as *const u8 as *const libc::c_char,
                nid: 22 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(124 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7-envelopedData\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs7-envelopedData\0" as *const u8 as *const libc::c_char,
                nid: 23 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(133 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7-signedAndEnvelopedData\0" as *const u8
                    as *const libc::c_char,
                ln: b"pkcs7-signedAndEnvelopedData\0" as *const u8
                    as *const libc::c_char,
                nid: 24 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(142 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7-digestData\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs7-digestData\0" as *const u8 as *const libc::c_char,
                nid: 25 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(151 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs7-encryptedData\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs7-encryptedData\0" as *const u8 as *const libc::c_char,
                nid: 26 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(160 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs3\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs3\0" as *const u8 as *const libc::c_char,
                nid: 27 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(169 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhKeyAgreement\0" as *const u8 as *const libc::c_char,
                ln: b"dhKeyAgreement\0" as *const u8 as *const libc::c_char,
                nid: 28 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(177 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"des-ecb\0" as *const u8 as *const libc::c_char,
                nid: 29 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(186 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"des-cfb\0" as *const u8 as *const libc::c_char,
                nid: 30 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(191 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"des-cbc\0" as *const u8 as *const libc::c_char,
                nid: 31 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(196 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede\0" as *const u8 as *const libc::c_char,
                nid: 32 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(201 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE3\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede3\0" as *const u8 as *const libc::c_char,
                nid: 33 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"IDEA-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"idea-cbc\0" as *const u8 as *const libc::c_char,
                nid: 34 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(206 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"IDEA-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"idea-cfb\0" as *const u8 as *const libc::c_char,
                nid: 35 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"IDEA-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"idea-ecb\0" as *const u8 as *const libc::c_char,
                nid: 36 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC2-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"rc2-cbc\0" as *const u8 as *const libc::c_char,
                nid: 37 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(217 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC2-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"rc2-ecb\0" as *const u8 as *const libc::c_char,
                nid: 38 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC2-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"rc2-cfb\0" as *const u8 as *const libc::c_char,
                nid: 39 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC2-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"rc2-ofb\0" as *const u8 as *const libc::c_char,
                nid: 40 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA\0" as *const u8 as *const libc::c_char,
                ln: b"sha\0" as *const u8 as *const libc::c_char,
                nid: 41 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(225 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA\0" as *const u8 as *const libc::c_char,
                ln: b"shaWithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 42 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(230 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede-cbc\0" as *const u8 as *const libc::c_char,
                nid: 43 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE3-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede3-cbc\0" as *const u8 as *const libc::c_char,
                nid: 44 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(235 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"des-ofb\0" as *const u8 as *const libc::c_char,
                nid: 45 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(243 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"IDEA-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"idea-ofb\0" as *const u8 as *const libc::c_char,
                nid: 46 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs9\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs9\0" as *const u8 as *const libc::c_char,
                nid: 47 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(248 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"emailAddress\0" as *const u8 as *const libc::c_char,
                ln: b"emailAddress\0" as *const u8 as *const libc::c_char,
                nid: 48 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(256 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"unstructuredName\0" as *const u8 as *const libc::c_char,
                ln: b"unstructuredName\0" as *const u8 as *const libc::c_char,
                nid: 49 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(265 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"contentType\0" as *const u8 as *const libc::c_char,
                ln: b"contentType\0" as *const u8 as *const libc::c_char,
                nid: 50 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(274 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"messageDigest\0" as *const u8 as *const libc::c_char,
                ln: b"messageDigest\0" as *const u8 as *const libc::c_char,
                nid: 51 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(283 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"signingTime\0" as *const u8 as *const libc::c_char,
                ln: b"signingTime\0" as *const u8 as *const libc::c_char,
                nid: 52 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(292 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"countersignature\0" as *const u8 as *const libc::c_char,
                ln: b"countersignature\0" as *const u8 as *const libc::c_char,
                nid: 53 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(301 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"challengePassword\0" as *const u8 as *const libc::c_char,
                ln: b"challengePassword\0" as *const u8 as *const libc::c_char,
                nid: 54 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(310 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"unstructuredAddress\0" as *const u8 as *const libc::c_char,
                ln: b"unstructuredAddress\0" as *const u8 as *const libc::c_char,
                nid: 55 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(319 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"extendedCertificateAttributes\0" as *const u8
                    as *const libc::c_char,
                ln: b"extendedCertificateAttributes\0" as *const u8
                    as *const libc::c_char,
                nid: 56 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(328 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"Netscape\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Communications Corp.\0" as *const u8
                    as *const libc::c_char,
                nid: 57 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(337 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsCertExt\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Certificate Extension\0" as *const u8
                    as *const libc::c_char,
                nid: 58 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(344 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsDataType\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Data Type\0" as *const u8 as *const libc::c_char,
                nid: 59 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(352 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede-cfb\0" as *const u8 as *const libc::c_char,
                nid: 60 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE3-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede3-cfb\0" as *const u8 as *const libc::c_char,
                nid: 61 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede-ofb\0" as *const u8 as *const libc::c_char,
                nid: 62 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE3-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede3-ofb\0" as *const u8 as *const libc::c_char,
                nid: 63 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"sha1\0" as *const u8 as *const libc::c_char,
                nid: 64 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(360 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"sha1WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 65 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(365 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DSA-SHA\0" as *const u8 as *const libc::c_char,
                ln: b"dsaWithSHA\0" as *const u8 as *const libc::c_char,
                nid: 66 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(374 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DSA-old\0" as *const u8 as *const libc::c_char,
                ln: b"dsaEncryption-old\0" as *const u8 as *const libc::c_char,
                nid: 67 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(379 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-RC2-64\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1AndRC2-CBC\0" as *const u8 as *const libc::c_char,
                nid: 68 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(384 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBKDF2\0" as *const u8 as *const libc::c_char,
                ln: b"PBKDF2\0" as *const u8 as *const libc::c_char,
                nid: 69 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(393 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DSA-SHA1-old\0" as *const u8 as *const libc::c_char,
                ln: b"dsaWithSHA1-old\0" as *const u8 as *const libc::c_char,
                nid: 70 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(402 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsCertType\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Cert Type\0" as *const u8 as *const libc::c_char,
                nid: 71 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(407 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsBaseUrl\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Base Url\0" as *const u8 as *const libc::c_char,
                nid: 72 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(416 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsRevocationUrl\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Revocation Url\0" as *const u8 as *const libc::c_char,
                nid: 73 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(425 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsCaRevocationUrl\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape CA Revocation Url\0" as *const u8 as *const libc::c_char,
                nid: 74 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(434 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsRenewalUrl\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Renewal Url\0" as *const u8 as *const libc::c_char,
                nid: 75 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(443 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsCaPolicyUrl\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape CA Policy Url\0" as *const u8 as *const libc::c_char,
                nid: 76 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(452 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsSslServerName\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape SSL Server Name\0" as *const u8 as *const libc::c_char,
                nid: 77 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(461 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsComment\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Comment\0" as *const u8 as *const libc::c_char,
                nid: 78 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(470 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsCertSequence\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Certificate Sequence\0" as *const u8
                    as *const libc::c_char,
                nid: 79 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(479 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DESX-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"desx-cbc\0" as *const u8 as *const libc::c_char,
                nid: 80 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ce\0" as *const u8 as *const libc::c_char,
                ln: b"id-ce\0" as *const u8 as *const libc::c_char,
                nid: 81 as libc::c_int,
                length: 2 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(488 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"subjectKeyIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Subject Key Identifier\0" as *const u8
                    as *const libc::c_char,
                nid: 82 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(490 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"keyUsage\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Key Usage\0" as *const u8 as *const libc::c_char,
                nid: 83 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(493 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"privateKeyUsagePeriod\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Private Key Usage Period\0" as *const u8
                    as *const libc::c_char,
                nid: 84 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(496 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"subjectAltName\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Subject Alternative Name\0" as *const u8
                    as *const libc::c_char,
                nid: 85 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(499 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"issuerAltName\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Issuer Alternative Name\0" as *const u8
                    as *const libc::c_char,
                nid: 86 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(502 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"basicConstraints\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Basic Constraints\0" as *const u8 as *const libc::c_char,
                nid: 87 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(505 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"crlNumber\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 CRL Number\0" as *const u8 as *const libc::c_char,
                nid: 88 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(508 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"certificatePolicies\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Certificate Policies\0" as *const u8 as *const libc::c_char,
                nid: 89 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(511 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"authorityKeyIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Authority Key Identifier\0" as *const u8
                    as *const libc::c_char,
                nid: 90 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(514 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"BF-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"bf-cbc\0" as *const u8 as *const libc::c_char,
                nid: 91 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(517 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"BF-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"bf-ecb\0" as *const u8 as *const libc::c_char,
                nid: 92 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"BF-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"bf-cfb\0" as *const u8 as *const libc::c_char,
                nid: 93 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"BF-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"bf-ofb\0" as *const u8 as *const libc::c_char,
                nid: 94 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MDC2\0" as *const u8 as *const libc::c_char,
                ln: b"mdc2\0" as *const u8 as *const libc::c_char,
                nid: 95 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(526 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-MDC2\0" as *const u8 as *const libc::c_char,
                ln: b"mdc2WithRSA\0" as *const u8 as *const libc::c_char,
                nid: 96 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(530 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC4-40\0" as *const u8 as *const libc::c_char,
                ln: b"rc4-40\0" as *const u8 as *const libc::c_char,
                nid: 97 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC2-40-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"rc2-40-cbc\0" as *const u8 as *const libc::c_char,
                nid: 98 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"GN\0" as *const u8 as *const libc::c_char,
                ln: b"givenName\0" as *const u8 as *const libc::c_char,
                nid: 99 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(534 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SN\0" as *const u8 as *const libc::c_char,
                ln: b"surname\0" as *const u8 as *const libc::c_char,
                nid: 100 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(537 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"initials\0" as *const u8 as *const libc::c_char,
                ln: b"initials\0" as *const u8 as *const libc::c_char,
                nid: 101 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(540 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"crlDistributionPoints\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 CRL Distribution Points\0" as *const u8
                    as *const libc::c_char,
                nid: 103 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(543 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-NP-MD5\0" as *const u8 as *const libc::c_char,
                ln: b"md5WithRSA\0" as *const u8 as *const libc::c_char,
                nid: 104 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(546 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"serialNumber\0" as *const u8 as *const libc::c_char,
                ln: b"serialNumber\0" as *const u8 as *const libc::c_char,
                nid: 105 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(551 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"title\0" as *const u8 as *const libc::c_char,
                ln: b"title\0" as *const u8 as *const libc::c_char,
                nid: 106 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(554 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"description\0" as *const u8 as *const libc::c_char,
                ln: b"description\0" as *const u8 as *const libc::c_char,
                nid: 107 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(557 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAST5-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"cast5-cbc\0" as *const u8 as *const libc::c_char,
                nid: 108 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(560 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAST5-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"cast5-ecb\0" as *const u8 as *const libc::c_char,
                nid: 109 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAST5-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"cast5-cfb\0" as *const u8 as *const libc::c_char,
                nid: 110 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAST5-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"cast5-ofb\0" as *const u8 as *const libc::c_char,
                nid: 111 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pbeWithMD5AndCast5CBC\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithMD5AndCast5CBC\0" as *const u8 as *const libc::c_char,
                nid: 112 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(569 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DSA-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"dsaWithSHA1\0" as *const u8 as *const libc::c_char,
                nid: 113 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(578 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MD5-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"md5-sha1\0" as *const u8 as *const libc::c_char,
                nid: 114 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA1-2\0" as *const u8 as *const libc::c_char,
                ln: b"sha1WithRSA\0" as *const u8 as *const libc::c_char,
                nid: 115 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(585 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DSA\0" as *const u8 as *const libc::c_char,
                ln: b"dsaEncryption\0" as *const u8 as *const libc::c_char,
                nid: 116 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(590 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RIPEMD160\0" as *const u8 as *const libc::c_char,
                ln: b"ripemd160\0" as *const u8 as *const libc::c_char,
                nid: 117 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(597 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-RIPEMD160\0" as *const u8 as *const libc::c_char,
                ln: b"ripemd160WithRSA\0" as *const u8 as *const libc::c_char,
                nid: 119 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(602 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC5-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"rc5-cbc\0" as *const u8 as *const libc::c_char,
                nid: 120 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(608 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC5-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"rc5-ecb\0" as *const u8 as *const libc::c_char,
                nid: 121 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC5-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"rc5-cfb\0" as *const u8 as *const libc::c_char,
                nid: 122 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC5-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"rc5-ofb\0" as *const u8 as *const libc::c_char,
                nid: 123 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ZLIB\0" as *const u8 as *const libc::c_char,
                ln: b"zlib compression\0" as *const u8 as *const libc::c_char,
                nid: 125 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(616 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"extendedKeyUsage\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Extended Key Usage\0" as *const u8 as *const libc::c_char,
                nid: 126 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(627 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PKIX\0" as *const u8 as *const libc::c_char,
                ln: b"PKIX\0" as *const u8 as *const libc::c_char,
                nid: 127 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(630 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-kp\0" as *const u8 as *const libc::c_char,
                ln: b"id-kp\0" as *const u8 as *const libc::c_char,
                nid: 128 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(636 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"serverAuth\0" as *const u8 as *const libc::c_char,
                ln: b"TLS Web Server Authentication\0" as *const u8
                    as *const libc::c_char,
                nid: 129 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(643 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"clientAuth\0" as *const u8 as *const libc::c_char,
                ln: b"TLS Web Client Authentication\0" as *const u8
                    as *const libc::c_char,
                nid: 130 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(651 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"codeSigning\0" as *const u8 as *const libc::c_char,
                ln: b"Code Signing\0" as *const u8 as *const libc::c_char,
                nid: 131 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(659 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"emailProtection\0" as *const u8 as *const libc::c_char,
                ln: b"E-mail Protection\0" as *const u8 as *const libc::c_char,
                nid: 132 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(667 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"timeStamping\0" as *const u8 as *const libc::c_char,
                ln: b"Time Stamping\0" as *const u8 as *const libc::c_char,
                nid: 133 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(675 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msCodeInd\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Individual Code Signing\0" as *const u8
                    as *const libc::c_char,
                nid: 134 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(683 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msCodeCom\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Commercial Code Signing\0" as *const u8
                    as *const libc::c_char,
                nid: 135 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(693 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msCTLSign\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Trust List Signing\0" as *const u8
                    as *const libc::c_char,
                nid: 136 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(703 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msSGC\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Server Gated Crypto\0" as *const u8
                    as *const libc::c_char,
                nid: 137 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(713 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msEFS\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Encrypted File System\0" as *const u8
                    as *const libc::c_char,
                nid: 138 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(723 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nsSGC\0" as *const u8 as *const libc::c_char,
                ln: b"Netscape Server Gated Crypto\0" as *const u8
                    as *const libc::c_char,
                nid: 139 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(733 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"deltaCRL\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Delta CRL Indicator\0" as *const u8 as *const libc::c_char,
                nid: 140 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(742 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CRLReason\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 CRL Reason Code\0" as *const u8 as *const libc::c_char,
                nid: 141 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(745 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"invalidityDate\0" as *const u8 as *const libc::c_char,
                ln: b"Invalidity Date\0" as *const u8 as *const libc::c_char,
                nid: 142 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(748 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SXNetID\0" as *const u8 as *const libc::c_char,
                ln: b"Strong Extranet ID\0" as *const u8 as *const libc::c_char,
                nid: 143 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(751 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-RC4-128\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1And128BitRC4\0" as *const u8 as *const libc::c_char,
                nid: 144 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(756 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-RC4-40\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1And40BitRC4\0" as *const u8 as *const libc::c_char,
                nid: 145 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(766 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-3DES\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1And3-KeyTripleDES-CBC\0" as *const u8
                    as *const libc::c_char,
                nid: 146 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(776 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-2DES\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1And2-KeyTripleDES-CBC\0" as *const u8
                    as *const libc::c_char,
                nid: 147 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(786 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-RC2-128\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1And128BitRC2-CBC\0" as *const u8 as *const libc::c_char,
                nid: 148 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(796 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-RC2-40\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1And40BitRC2-CBC\0" as *const u8 as *const libc::c_char,
                nid: 149 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(806 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"keyBag\0" as *const u8 as *const libc::c_char,
                ln: b"keyBag\0" as *const u8 as *const libc::c_char,
                nid: 150 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(816 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs8ShroudedKeyBag\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs8ShroudedKeyBag\0" as *const u8 as *const libc::c_char,
                nid: 151 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(827 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"certBag\0" as *const u8 as *const libc::c_char,
                ln: b"certBag\0" as *const u8 as *const libc::c_char,
                nid: 152 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(838 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"crlBag\0" as *const u8 as *const libc::c_char,
                ln: b"crlBag\0" as *const u8 as *const libc::c_char,
                nid: 153 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(849 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secretBag\0" as *const u8 as *const libc::c_char,
                ln: b"secretBag\0" as *const u8 as *const libc::c_char,
                nid: 154 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(860 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"safeContentsBag\0" as *const u8 as *const libc::c_char,
                ln: b"safeContentsBag\0" as *const u8 as *const libc::c_char,
                nid: 155 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(871 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"friendlyName\0" as *const u8 as *const libc::c_char,
                ln: b"friendlyName\0" as *const u8 as *const libc::c_char,
                nid: 156 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(882 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"localKeyID\0" as *const u8 as *const libc::c_char,
                ln: b"localKeyID\0" as *const u8 as *const libc::c_char,
                nid: 157 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(891 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"x509Certificate\0" as *const u8 as *const libc::c_char,
                ln: b"x509Certificate\0" as *const u8 as *const libc::c_char,
                nid: 158 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(900 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sdsiCertificate\0" as *const u8 as *const libc::c_char,
                ln: b"sdsiCertificate\0" as *const u8 as *const libc::c_char,
                nid: 159 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(910 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"x509Crl\0" as *const u8 as *const libc::c_char,
                ln: b"x509Crl\0" as *const u8 as *const libc::c_char,
                nid: 160 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(920 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBES2\0" as *const u8 as *const libc::c_char,
                ln: b"PBES2\0" as *const u8 as *const libc::c_char,
                nid: 161 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(930 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBMAC1\0" as *const u8 as *const libc::c_char,
                ln: b"PBMAC1\0" as *const u8 as *const libc::c_char,
                nid: 162 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(939 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"hmacWithSHA1\0" as *const u8 as *const libc::c_char,
                ln: b"hmacWithSHA1\0" as *const u8 as *const libc::c_char,
                nid: 163 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(948 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-qt-cps\0" as *const u8 as *const libc::c_char,
                ln: b"Policy Qualifier CPS\0" as *const u8 as *const libc::c_char,
                nid: 164 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(956 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-qt-unotice\0" as *const u8 as *const libc::c_char,
                ln: b"Policy Qualifier User Notice\0" as *const u8
                    as *const libc::c_char,
                nid: 165 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(964 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC2-64-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"rc2-64-cbc\0" as *const u8 as *const libc::c_char,
                nid: 166 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SMIME-CAPS\0" as *const u8 as *const libc::c_char,
                ln: b"S/MIME Capabilities\0" as *const u8 as *const libc::c_char,
                nid: 167 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(972 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-MD2-RC2-64\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithMD2AndRC2-CBC\0" as *const u8 as *const libc::c_char,
                nid: 168 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(981 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-MD5-RC2-64\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithMD5AndRC2-CBC\0" as *const u8 as *const libc::c_char,
                nid: 169 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(990 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PBE-SHA1-DES\0" as *const u8 as *const libc::c_char,
                ln: b"pbeWithSHA1AndDES-CBC\0" as *const u8 as *const libc::c_char,
                nid: 170 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(999 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msExtReq\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Extension Request\0" as *const u8 as *const libc::c_char,
                nid: 171 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1008 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"extReq\0" as *const u8 as *const libc::c_char,
                ln: b"Extension Request\0" as *const u8 as *const libc::c_char,
                nid: 172 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1018 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"name\0" as *const u8 as *const libc::c_char,
                ln: b"name\0" as *const u8 as *const libc::c_char,
                nid: 173 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1027 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dnQualifier\0" as *const u8 as *const libc::c_char,
                ln: b"dnQualifier\0" as *const u8 as *const libc::c_char,
                nid: 174 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1030 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pe\0" as *const u8 as *const libc::c_char,
                ln: b"id-pe\0" as *const u8 as *const libc::c_char,
                nid: 175 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1033 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ad\0" as *const u8 as *const libc::c_char,
                ln: b"id-ad\0" as *const u8 as *const libc::c_char,
                nid: 176 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1040 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"authorityInfoAccess\0" as *const u8 as *const libc::c_char,
                ln: b"Authority Information Access\0" as *const u8
                    as *const libc::c_char,
                nid: 177 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1047 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"OCSP\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP\0" as *const u8 as *const libc::c_char,
                nid: 178 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1055 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"caIssuers\0" as *const u8 as *const libc::c_char,
                ln: b"CA Issuers\0" as *const u8 as *const libc::c_char,
                nid: 179 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1063 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"OCSPSigning\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP Signing\0" as *const u8 as *const libc::c_char,
                nid: 180 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1071 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ISO\0" as *const u8 as *const libc::c_char,
                ln: b"iso\0" as *const u8 as *const libc::c_char,
                nid: 181 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"member-body\0" as *const u8 as *const libc::c_char,
                ln: b"ISO Member Body\0" as *const u8 as *const libc::c_char,
                nid: 182 as libc::c_int,
                length: 1 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1079 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ISO-US\0" as *const u8 as *const libc::c_char,
                ln: b"ISO US Member Body\0" as *const u8 as *const libc::c_char,
                nid: 183 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1080 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X9-57\0" as *const u8 as *const libc::c_char,
                ln: b"X9.57\0" as *const u8 as *const libc::c_char,
                nid: 184 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1083 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X9cm\0" as *const u8 as *const libc::c_char,
                ln: b"X9.57 CM ?\0" as *const u8 as *const libc::c_char,
                nid: 185 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1088 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs1\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs1\0" as *const u8 as *const libc::c_char,
                nid: 186 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1094 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pkcs5\0" as *const u8 as *const libc::c_char,
                ln: b"pkcs5\0" as *const u8 as *const libc::c_char,
                nid: 187 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1102 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SMIME\0" as *const u8 as *const libc::c_char,
                ln: b"S/MIME\0" as *const u8 as *const libc::c_char,
                nid: 188 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1110 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-mod\0" as *const u8 as *const libc::c_char,
                nid: 189 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1119 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct\0" as *const u8 as *const libc::c_char,
                nid: 190 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1129 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa\0" as *const u8 as *const libc::c_char,
                nid: 191 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1139 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg\0" as *const u8 as *const libc::c_char,
                nid: 192 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1149 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cd\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-cd\0" as *const u8 as *const libc::c_char,
                nid: 193 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1159 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-spq\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-spq\0" as *const u8 as *const libc::c_char,
                nid: 194 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1169 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-cti\0" as *const u8 as *const libc::c_char,
                nid: 195 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1179 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-cms\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-mod-cms\0" as *const u8 as *const libc::c_char,
                nid: 196 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1189 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-ess\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-mod-ess\0" as *const u8 as *const libc::c_char,
                nid: 197 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1200 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-oid\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-mod-oid\0" as *const u8 as *const libc::c_char,
                nid: 198 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1211 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-msg-v3\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-mod-msg-v3\0" as *const u8 as *const libc::c_char,
                nid: 199 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1222 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-ets-eSignature-88\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-mod-ets-eSignature-88\0" as *const u8
                    as *const libc::c_char,
                nid: 200 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1233 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-ets-eSignature-97\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-mod-ets-eSignature-97\0" as *const u8
                    as *const libc::c_char,
                nid: 201 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1244 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-ets-eSigPolicy-88\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-mod-ets-eSigPolicy-88\0" as *const u8
                    as *const libc::c_char,
                nid: 202 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1255 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-mod-ets-eSigPolicy-97\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-mod-ets-eSigPolicy-97\0" as *const u8
                    as *const libc::c_char,
                nid: 203 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1266 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-receipt\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-receipt\0" as *const u8 as *const libc::c_char,
                nid: 204 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1277 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-authData\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-authData\0" as *const u8 as *const libc::c_char,
                nid: 205 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1288 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-publishCert\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-publishCert\0" as *const u8 as *const libc::c_char,
                nid: 206 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1299 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-TSTInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-TSTInfo\0" as *const u8 as *const libc::c_char,
                nid: 207 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1310 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-TDTInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-TDTInfo\0" as *const u8 as *const libc::c_char,
                nid: 208 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1321 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-contentInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-contentInfo\0" as *const u8 as *const libc::c_char,
                nid: 209 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1332 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-DVCSRequestData\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-DVCSRequestData\0" as *const u8 as *const libc::c_char,
                nid: 210 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1343 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-DVCSResponseData\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-ct-DVCSResponseData\0" as *const u8
                    as *const libc::c_char,
                nid: 211 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1354 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-receiptRequest\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-receiptRequest\0" as *const u8 as *const libc::c_char,
                nid: 212 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1365 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-securityLabel\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-securityLabel\0" as *const u8 as *const libc::c_char,
                nid: 213 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1376 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-mlExpandHistory\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-mlExpandHistory\0" as *const u8 as *const libc::c_char,
                nid: 214 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1387 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-contentHint\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-contentHint\0" as *const u8 as *const libc::c_char,
                nid: 215 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1398 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-msgSigDigest\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-msgSigDigest\0" as *const u8 as *const libc::c_char,
                nid: 216 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1409 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-encapContentType\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-encapContentType\0" as *const u8
                    as *const libc::c_char,
                nid: 217 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1420 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-contentIdentifier\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-contentIdentifier\0" as *const u8
                    as *const libc::c_char,
                nid: 218 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1431 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-macValue\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-macValue\0" as *const u8 as *const libc::c_char,
                nid: 219 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1442 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-equivalentLabels\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-equivalentLabels\0" as *const u8
                    as *const libc::c_char,
                nid: 220 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1453 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-contentReference\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-contentReference\0" as *const u8
                    as *const libc::c_char,
                nid: 221 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1464 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-encrypKeyPref\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-encrypKeyPref\0" as *const u8 as *const libc::c_char,
                nid: 222 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1475 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-signingCertificate\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-signingCertificate\0" as *const u8
                    as *const libc::c_char,
                nid: 223 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1486 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-smimeEncryptCerts\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-smimeEncryptCerts\0" as *const u8
                    as *const libc::c_char,
                nid: 224 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1497 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-timeStampToken\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-timeStampToken\0" as *const u8 as *const libc::c_char,
                nid: 225 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1508 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-sigPolicyId\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-ets-sigPolicyId\0" as *const u8 as *const libc::c_char,
                nid: 226 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1519 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-commitmentType\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-commitmentType\0" as *const u8
                    as *const libc::c_char,
                nid: 227 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1530 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-signerLocation\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-signerLocation\0" as *const u8
                    as *const libc::c_char,
                nid: 228 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1541 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-signerAttr\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-ets-signerAttr\0" as *const u8 as *const libc::c_char,
                nid: 229 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1552 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-otherSigCert\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-otherSigCert\0" as *const u8
                    as *const libc::c_char,
                nid: 230 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1563 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-contentTimestamp\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-contentTimestamp\0" as *const u8
                    as *const libc::c_char,
                nid: 231 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1574 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-CertificateRefs\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-CertificateRefs\0" as *const u8
                    as *const libc::c_char,
                nid: 232 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1585 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-RevocationRefs\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-RevocationRefs\0" as *const u8
                    as *const libc::c_char,
                nid: 233 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1596 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-certValues\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-ets-certValues\0" as *const u8 as *const libc::c_char,
                nid: 234 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1607 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-revocationValues\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-revocationValues\0" as *const u8
                    as *const libc::c_char,
                nid: 235 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1618 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-escTimeStamp\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-escTimeStamp\0" as *const u8
                    as *const libc::c_char,
                nid: 236 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1629 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-certCRLTimestamp\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-certCRLTimestamp\0" as *const u8
                    as *const libc::c_char,
                nid: 237 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1640 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-ets-archiveTimeStamp\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-aa-ets-archiveTimeStamp\0" as *const u8
                    as *const libc::c_char,
                nid: 238 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1651 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-signatureType\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-signatureType\0" as *const u8 as *const libc::c_char,
                nid: 239 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1662 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-aa-dvcs-dvc\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-aa-dvcs-dvc\0" as *const u8 as *const libc::c_char,
                nid: 240 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1673 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-ESDHwith3DES\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-ESDHwith3DES\0" as *const u8 as *const libc::c_char,
                nid: 241 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1684 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-ESDHwithRC2\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-ESDHwithRC2\0" as *const u8 as *const libc::c_char,
                nid: 242 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1695 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-3DESwrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-3DESwrap\0" as *const u8 as *const libc::c_char,
                nid: 243 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1706 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-RC2wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-RC2wrap\0" as *const u8 as *const libc::c_char,
                nid: 244 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1717 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-ESDH\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-ESDH\0" as *const u8 as *const libc::c_char,
                nid: 245 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1728 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-CMS3DESwrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-CMS3DESwrap\0" as *const u8 as *const libc::c_char,
                nid: 246 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1739 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-alg-CMSRC2wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-alg-CMSRC2wrap\0" as *const u8 as *const libc::c_char,
                nid: 247 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1750 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cd-ldap\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-cd-ldap\0" as *const u8 as *const libc::c_char,
                nid: 248 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1761 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-spq-ets-sqt-uri\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-spq-ets-sqt-uri\0" as *const u8 as *const libc::c_char,
                nid: 249 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1772 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-spq-ets-sqt-unotice\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-spq-ets-sqt-unotice\0" as *const u8
                    as *const libc::c_char,
                nid: 250 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1783 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti-ets-proofOfOrigin\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-cti-ets-proofOfOrigin\0" as *const u8
                    as *const libc::c_char,
                nid: 251 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1794 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti-ets-proofOfReceipt\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-cti-ets-proofOfReceipt\0" as *const u8
                    as *const libc::c_char,
                nid: 252 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1805 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti-ets-proofOfDelivery\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-cti-ets-proofOfDelivery\0" as *const u8
                    as *const libc::c_char,
                nid: 253 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1816 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti-ets-proofOfSender\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-cti-ets-proofOfSender\0" as *const u8
                    as *const libc::c_char,
                nid: 254 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1827 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti-ets-proofOfApproval\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-cti-ets-proofOfApproval\0" as *const u8
                    as *const libc::c_char,
                nid: 255 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1838 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-cti-ets-proofOfCreation\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-smime-cti-ets-proofOfCreation\0" as *const u8
                    as *const libc::c_char,
                nid: 256 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1849 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MD4\0" as *const u8 as *const libc::c_char,
                ln: b"md4\0" as *const u8 as *const libc::c_char,
                nid: 257 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1860 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pkix-mod\0" as *const u8 as *const libc::c_char,
                ln: b"id-pkix-mod\0" as *const u8 as *const libc::c_char,
                nid: 258 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1868 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-qt\0" as *const u8 as *const libc::c_char,
                ln: b"id-qt\0" as *const u8 as *const libc::c_char,
                nid: 259 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1875 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it\0" as *const u8 as *const libc::c_char,
                ln: b"id-it\0" as *const u8 as *const libc::c_char,
                nid: 260 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1882 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pkip\0" as *const u8 as *const libc::c_char,
                ln: b"id-pkip\0" as *const u8 as *const libc::c_char,
                nid: 261 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1889 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-alg\0" as *const u8 as *const libc::c_char,
                ln: b"id-alg\0" as *const u8 as *const libc::c_char,
                nid: 262 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1896 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc\0" as *const u8 as *const libc::c_char,
                nid: 263 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1903 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-on\0" as *const u8 as *const libc::c_char,
                ln: b"id-on\0" as *const u8 as *const libc::c_char,
                nid: 264 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1910 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pda\0" as *const u8 as *const libc::c_char,
                ln: b"id-pda\0" as *const u8 as *const libc::c_char,
                nid: 265 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1917 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca\0" as *const u8 as *const libc::c_char,
                nid: 266 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1924 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-qcs\0" as *const u8 as *const libc::c_char,
                ln: b"id-qcs\0" as *const u8 as *const libc::c_char,
                nid: 267 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1931 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cct\0" as *const u8 as *const libc::c_char,
                ln: b"id-cct\0" as *const u8 as *const libc::c_char,
                nid: 268 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1938 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pkix1-explicit-88\0" as *const u8 as *const libc::c_char,
                ln: b"id-pkix1-explicit-88\0" as *const u8 as *const libc::c_char,
                nid: 269 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1945 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pkix1-implicit-88\0" as *const u8 as *const libc::c_char,
                ln: b"id-pkix1-implicit-88\0" as *const u8 as *const libc::c_char,
                nid: 270 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1953 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pkix1-explicit-93\0" as *const u8 as *const libc::c_char,
                ln: b"id-pkix1-explicit-93\0" as *const u8 as *const libc::c_char,
                nid: 271 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1961 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pkix1-implicit-93\0" as *const u8 as *const libc::c_char,
                ln: b"id-pkix1-implicit-93\0" as *const u8 as *const libc::c_char,
                nid: 272 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1969 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-crmf\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-crmf\0" as *const u8 as *const libc::c_char,
                nid: 273 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1977 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-cmc\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-cmc\0" as *const u8 as *const libc::c_char,
                nid: 274 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1985 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-kea-profile-88\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-kea-profile-88\0" as *const u8 as *const libc::c_char,
                nid: 275 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(1993 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-kea-profile-93\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-kea-profile-93\0" as *const u8 as *const libc::c_char,
                nid: 276 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2001 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-cmp\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-cmp\0" as *const u8 as *const libc::c_char,
                nid: 277 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2009 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-qualified-cert-88\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-qualified-cert-88\0" as *const u8 as *const libc::c_char,
                nid: 278 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2017 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-qualified-cert-93\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-qualified-cert-93\0" as *const u8 as *const libc::c_char,
                nid: 279 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2025 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-attribute-cert\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-attribute-cert\0" as *const u8 as *const libc::c_char,
                nid: 280 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2033 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-timestamp-protocol\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-timestamp-protocol\0" as *const u8 as *const libc::c_char,
                nid: 281 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2041 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-ocsp\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-ocsp\0" as *const u8 as *const libc::c_char,
                nid: 282 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2049 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-dvcs\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-dvcs\0" as *const u8 as *const libc::c_char,
                nid: 283 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2057 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-mod-cmp2000\0" as *const u8 as *const libc::c_char,
                ln: b"id-mod-cmp2000\0" as *const u8 as *const libc::c_char,
                nid: 284 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2065 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"biometricInfo\0" as *const u8 as *const libc::c_char,
                ln: b"Biometric Info\0" as *const u8 as *const libc::c_char,
                nid: 285 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2073 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"qcStatements\0" as *const u8 as *const libc::c_char,
                ln: b"qcStatements\0" as *const u8 as *const libc::c_char,
                nid: 286 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2081 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ac-auditEntity\0" as *const u8 as *const libc::c_char,
                ln: b"ac-auditEntity\0" as *const u8 as *const libc::c_char,
                nid: 287 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2089 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ac-targeting\0" as *const u8 as *const libc::c_char,
                ln: b"ac-targeting\0" as *const u8 as *const libc::c_char,
                nid: 288 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2097 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"aaControls\0" as *const u8 as *const libc::c_char,
                ln: b"aaControls\0" as *const u8 as *const libc::c_char,
                nid: 289 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2105 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sbgp-ipAddrBlock\0" as *const u8 as *const libc::c_char,
                ln: b"sbgp-ipAddrBlock\0" as *const u8 as *const libc::c_char,
                nid: 290 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2113 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sbgp-autonomousSysNum\0" as *const u8 as *const libc::c_char,
                ln: b"sbgp-autonomousSysNum\0" as *const u8 as *const libc::c_char,
                nid: 291 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2121 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sbgp-routerIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"sbgp-routerIdentifier\0" as *const u8 as *const libc::c_char,
                nid: 292 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2129 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"textNotice\0" as *const u8 as *const libc::c_char,
                ln: b"textNotice\0" as *const u8 as *const libc::c_char,
                nid: 293 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2137 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ipsecEndSystem\0" as *const u8 as *const libc::c_char,
                ln: b"IPSec End System\0" as *const u8 as *const libc::c_char,
                nid: 294 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2145 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ipsecTunnel\0" as *const u8 as *const libc::c_char,
                ln: b"IPSec Tunnel\0" as *const u8 as *const libc::c_char,
                nid: 295 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2153 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ipsecUser\0" as *const u8 as *const libc::c_char,
                ln: b"IPSec User\0" as *const u8 as *const libc::c_char,
                nid: 296 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2161 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DVCS\0" as *const u8 as *const libc::c_char,
                ln: b"dvcs\0" as *const u8 as *const libc::c_char,
                nid: 297 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2169 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-caProtEncCert\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-caProtEncCert\0" as *const u8 as *const libc::c_char,
                nid: 298 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2177 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-signKeyPairTypes\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-signKeyPairTypes\0" as *const u8 as *const libc::c_char,
                nid: 299 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2185 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-encKeyPairTypes\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-encKeyPairTypes\0" as *const u8 as *const libc::c_char,
                nid: 300 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2193 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-preferredSymmAlg\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-preferredSymmAlg\0" as *const u8 as *const libc::c_char,
                nid: 301 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2201 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-caKeyUpdateInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-caKeyUpdateInfo\0" as *const u8 as *const libc::c_char,
                nid: 302 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2209 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-currentCRL\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-currentCRL\0" as *const u8 as *const libc::c_char,
                nid: 303 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2217 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-unsupportedOIDs\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-unsupportedOIDs\0" as *const u8 as *const libc::c_char,
                nid: 304 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2225 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-subscriptionRequest\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-subscriptionRequest\0" as *const u8 as *const libc::c_char,
                nid: 305 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2233 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-subscriptionResponse\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-subscriptionResponse\0" as *const u8 as *const libc::c_char,
                nid: 306 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2241 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-keyPairParamReq\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-keyPairParamReq\0" as *const u8 as *const libc::c_char,
                nid: 307 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2249 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-keyPairParamRep\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-keyPairParamRep\0" as *const u8 as *const libc::c_char,
                nid: 308 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2257 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-revPassphrase\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-revPassphrase\0" as *const u8 as *const libc::c_char,
                nid: 309 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2265 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-implicitConfirm\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-implicitConfirm\0" as *const u8 as *const libc::c_char,
                nid: 310 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2273 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-confirmWaitTime\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-confirmWaitTime\0" as *const u8 as *const libc::c_char,
                nid: 311 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2281 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-origPKIMessage\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-origPKIMessage\0" as *const u8 as *const libc::c_char,
                nid: 312 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2289 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl\0" as *const u8 as *const libc::c_char,
                ln: b"id-regCtrl\0" as *const u8 as *const libc::c_char,
                nid: 313 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2297 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-regInfo\0" as *const u8 as *const libc::c_char,
                nid: 314 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2305 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl-regToken\0" as *const u8 as *const libc::c_char,
                ln: b"id-regCtrl-regToken\0" as *const u8 as *const libc::c_char,
                nid: 315 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2313 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl-authenticator\0" as *const u8 as *const libc::c_char,
                ln: b"id-regCtrl-authenticator\0" as *const u8 as *const libc::c_char,
                nid: 316 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2322 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl-pkiPublicationInfo\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-regCtrl-pkiPublicationInfo\0" as *const u8
                    as *const libc::c_char,
                nid: 317 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2331 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl-pkiArchiveOptions\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-regCtrl-pkiArchiveOptions\0" as *const u8
                    as *const libc::c_char,
                nid: 318 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2340 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl-oldCertID\0" as *const u8 as *const libc::c_char,
                ln: b"id-regCtrl-oldCertID\0" as *const u8 as *const libc::c_char,
                nid: 319 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2349 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regCtrl-protocolEncrKey\0" as *const u8 as *const libc::c_char,
                ln: b"id-regCtrl-protocolEncrKey\0" as *const u8 as *const libc::c_char,
                nid: 320 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2358 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regInfo-utf8Pairs\0" as *const u8 as *const libc::c_char,
                ln: b"id-regInfo-utf8Pairs\0" as *const u8 as *const libc::c_char,
                nid: 321 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2367 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-regInfo-certReq\0" as *const u8 as *const libc::c_char,
                ln: b"id-regInfo-certReq\0" as *const u8 as *const libc::c_char,
                nid: 322 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2376 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-alg-des40\0" as *const u8 as *const libc::c_char,
                ln: b"id-alg-des40\0" as *const u8 as *const libc::c_char,
                nid: 323 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2385 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-alg-noSignature\0" as *const u8 as *const libc::c_char,
                ln: b"id-alg-noSignature\0" as *const u8 as *const libc::c_char,
                nid: 324 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2393 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-alg-dh-sig-hmac-sha1\0" as *const u8 as *const libc::c_char,
                ln: b"id-alg-dh-sig-hmac-sha1\0" as *const u8 as *const libc::c_char,
                nid: 325 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2401 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-alg-dh-pop\0" as *const u8 as *const libc::c_char,
                ln: b"id-alg-dh-pop\0" as *const u8 as *const libc::c_char,
                nid: 326 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2409 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-statusInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-statusInfo\0" as *const u8 as *const libc::c_char,
                nid: 327 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2417 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-identification\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-identification\0" as *const u8 as *const libc::c_char,
                nid: 328 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2425 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-identityProof\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-identityProof\0" as *const u8 as *const libc::c_char,
                nid: 329 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2433 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-dataReturn\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-dataReturn\0" as *const u8 as *const libc::c_char,
                nid: 330 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2441 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-transactionId\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-transactionId\0" as *const u8 as *const libc::c_char,
                nid: 331 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2449 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-senderNonce\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-senderNonce\0" as *const u8 as *const libc::c_char,
                nid: 332 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2457 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-recipientNonce\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-recipientNonce\0" as *const u8 as *const libc::c_char,
                nid: 333 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2465 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-addExtensions\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-addExtensions\0" as *const u8 as *const libc::c_char,
                nid: 334 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2473 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-encryptedPOP\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-encryptedPOP\0" as *const u8 as *const libc::c_char,
                nid: 335 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2481 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-decryptedPOP\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-decryptedPOP\0" as *const u8 as *const libc::c_char,
                nid: 336 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2489 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-lraPOPWitness\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-lraPOPWitness\0" as *const u8 as *const libc::c_char,
                nid: 337 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2497 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-getCert\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-getCert\0" as *const u8 as *const libc::c_char,
                nid: 338 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2505 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-getCRL\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-getCRL\0" as *const u8 as *const libc::c_char,
                nid: 339 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2513 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-revokeRequest\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-revokeRequest\0" as *const u8 as *const libc::c_char,
                nid: 340 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2521 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-regInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-regInfo\0" as *const u8 as *const libc::c_char,
                nid: 341 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2529 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-responseInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-responseInfo\0" as *const u8 as *const libc::c_char,
                nid: 342 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2537 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-queryPending\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-queryPending\0" as *const u8 as *const libc::c_char,
                nid: 343 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2545 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-popLinkRandom\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-popLinkRandom\0" as *const u8 as *const libc::c_char,
                nid: 344 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2553 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-popLinkWitness\0" as *const u8 as *const libc::c_char,
                ln: b"id-cmc-popLinkWitness\0" as *const u8 as *const libc::c_char,
                nid: 345 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2561 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cmc-confirmCertAcceptance\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-cmc-confirmCertAcceptance\0" as *const u8
                    as *const libc::c_char,
                nid: 346 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2569 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-on-personalData\0" as *const u8 as *const libc::c_char,
                ln: b"id-on-personalData\0" as *const u8 as *const libc::c_char,
                nid: 347 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2577 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pda-dateOfBirth\0" as *const u8 as *const libc::c_char,
                ln: b"id-pda-dateOfBirth\0" as *const u8 as *const libc::c_char,
                nid: 348 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2585 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pda-placeOfBirth\0" as *const u8 as *const libc::c_char,
                ln: b"id-pda-placeOfBirth\0" as *const u8 as *const libc::c_char,
                nid: 349 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2593 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pda-gender\0" as *const u8 as *const libc::c_char,
                ln: b"id-pda-gender\0" as *const u8 as *const libc::c_char,
                nid: 351 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2601 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pda-countryOfCitizenship\0" as *const u8 as *const libc::c_char,
                ln: b"id-pda-countryOfCitizenship\0" as *const u8 as *const libc::c_char,
                nid: 352 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2609 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-pda-countryOfResidence\0" as *const u8 as *const libc::c_char,
                ln: b"id-pda-countryOfResidence\0" as *const u8 as *const libc::c_char,
                nid: 353 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2617 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca-authenticationInfo\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca-authenticationInfo\0" as *const u8 as *const libc::c_char,
                nid: 354 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2625 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca-accessIdentity\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca-accessIdentity\0" as *const u8 as *const libc::c_char,
                nid: 355 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2633 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca-chargingIdentity\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca-chargingIdentity\0" as *const u8 as *const libc::c_char,
                nid: 356 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2641 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca-group\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca-group\0" as *const u8 as *const libc::c_char,
                nid: 357 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2649 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca-role\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca-role\0" as *const u8 as *const libc::c_char,
                nid: 358 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2657 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-qcs-pkixQCSyntax-v1\0" as *const u8 as *const libc::c_char,
                ln: b"id-qcs-pkixQCSyntax-v1\0" as *const u8 as *const libc::c_char,
                nid: 359 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2665 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cct-crs\0" as *const u8 as *const libc::c_char,
                ln: b"id-cct-crs\0" as *const u8 as *const libc::c_char,
                nid: 360 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2673 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cct-PKIData\0" as *const u8 as *const libc::c_char,
                ln: b"id-cct-PKIData\0" as *const u8 as *const libc::c_char,
                nid: 361 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2681 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-cct-PKIResponse\0" as *const u8 as *const libc::c_char,
                ln: b"id-cct-PKIResponse\0" as *const u8 as *const libc::c_char,
                nid: 362 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2689 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ad_timestamping\0" as *const u8 as *const libc::c_char,
                ln: b"AD Time Stamping\0" as *const u8 as *const libc::c_char,
                nid: 363 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2697 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AD_DVCS\0" as *const u8 as *const libc::c_char,
                ln: b"ad dvcs\0" as *const u8 as *const libc::c_char,
                nid: 364 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2705 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"basicOCSPResponse\0" as *const u8 as *const libc::c_char,
                ln: b"Basic OCSP Response\0" as *const u8 as *const libc::c_char,
                nid: 365 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2713 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"Nonce\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP Nonce\0" as *const u8 as *const libc::c_char,
                nid: 366 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2722 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CrlID\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP CRL ID\0" as *const u8 as *const libc::c_char,
                nid: 367 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2731 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"acceptableResponses\0" as *const u8 as *const libc::c_char,
                ln: b"Acceptable OCSP Responses\0" as *const u8 as *const libc::c_char,
                nid: 368 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2740 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"noCheck\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP No Check\0" as *const u8 as *const libc::c_char,
                nid: 369 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2749 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"archiveCutoff\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP Archive Cutoff\0" as *const u8 as *const libc::c_char,
                nid: 370 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2758 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"serviceLocator\0" as *const u8 as *const libc::c_char,
                ln: b"OCSP Service Locator\0" as *const u8 as *const libc::c_char,
                nid: 371 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2767 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"extendedStatus\0" as *const u8 as *const libc::c_char,
                ln: b"Extended OCSP Status\0" as *const u8 as *const libc::c_char,
                nid: 372 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2776 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"valid\0" as *const u8 as *const libc::c_char,
                ln: b"valid\0" as *const u8 as *const libc::c_char,
                nid: 373 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2785 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"path\0" as *const u8 as *const libc::c_char,
                ln: b"path\0" as *const u8 as *const libc::c_char,
                nid: 374 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2794 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"trustRoot\0" as *const u8 as *const libc::c_char,
                ln: b"Trust Root\0" as *const u8 as *const libc::c_char,
                nid: 375 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2803 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"algorithm\0" as *const u8 as *const libc::c_char,
                ln: b"algorithm\0" as *const u8 as *const libc::c_char,
                nid: 376 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2812 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"rsaSignature\0" as *const u8 as *const libc::c_char,
                ln: b"rsaSignature\0" as *const u8 as *const libc::c_char,
                nid: 377 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2816 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X500algorithms\0" as *const u8 as *const libc::c_char,
                ln: b"directory services - algorithms\0" as *const u8
                    as *const libc::c_char,
                nid: 378 as libc::c_int,
                length: 2 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2821 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ORG\0" as *const u8 as *const libc::c_char,
                ln: b"org\0" as *const u8 as *const libc::c_char,
                nid: 379 as libc::c_int,
                length: 1 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2823 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DOD\0" as *const u8 as *const libc::c_char,
                ln: b"dod\0" as *const u8 as *const libc::c_char,
                nid: 380 as libc::c_int,
                length: 2 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2824 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"IANA\0" as *const u8 as *const libc::c_char,
                ln: b"iana\0" as *const u8 as *const libc::c_char,
                nid: 381 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2826 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"directory\0" as *const u8 as *const libc::c_char,
                ln: b"Directory\0" as *const u8 as *const libc::c_char,
                nid: 382 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2829 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mgmt\0" as *const u8 as *const libc::c_char,
                ln: b"Management\0" as *const u8 as *const libc::c_char,
                nid: 383 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2833 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"experimental\0" as *const u8 as *const libc::c_char,
                ln: b"Experimental\0" as *const u8 as *const libc::c_char,
                nid: 384 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2837 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"private\0" as *const u8 as *const libc::c_char,
                ln: b"Private\0" as *const u8 as *const libc::c_char,
                nid: 385 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2841 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"security\0" as *const u8 as *const libc::c_char,
                ln: b"Security\0" as *const u8 as *const libc::c_char,
                nid: 386 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2845 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"snmpv2\0" as *const u8 as *const libc::c_char,
                ln: b"SNMPv2\0" as *const u8 as *const libc::c_char,
                nid: 387 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2849 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"Mail\0" as *const u8 as *const libc::c_char,
                ln: b"Mail\0" as *const u8 as *const libc::c_char,
                nid: 388 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2853 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"enterprises\0" as *const u8 as *const libc::c_char,
                ln: b"Enterprises\0" as *const u8 as *const libc::c_char,
                nid: 389 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2857 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dcobject\0" as *const u8 as *const libc::c_char,
                ln: b"dcObject\0" as *const u8 as *const libc::c_char,
                nid: 390 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2862 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DC\0" as *const u8 as *const libc::c_char,
                ln: b"domainComponent\0" as *const u8 as *const libc::c_char,
                nid: 391 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2871 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"domain\0" as *const u8 as *const libc::c_char,
                ln: b"Domain\0" as *const u8 as *const libc::c_char,
                nid: 392 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2881 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"selected-attribute-types\0" as *const u8 as *const libc::c_char,
                ln: b"Selected Attribute Types\0" as *const u8 as *const libc::c_char,
                nid: 394 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2891 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"clearance\0" as *const u8 as *const libc::c_char,
                ln: b"clearance\0" as *const u8 as *const libc::c_char,
                nid: 395 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2894 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-MD4\0" as *const u8 as *const libc::c_char,
                ln: b"md4WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 396 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2898 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ac-proxying\0" as *const u8 as *const libc::c_char,
                ln: b"ac-proxying\0" as *const u8 as *const libc::c_char,
                nid: 397 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2907 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"subjectInfoAccess\0" as *const u8 as *const libc::c_char,
                ln: b"Subject Information Access\0" as *const u8 as *const libc::c_char,
                nid: 398 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2915 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aca-encAttrs\0" as *const u8 as *const libc::c_char,
                ln: b"id-aca-encAttrs\0" as *const u8 as *const libc::c_char,
                nid: 399 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2923 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"role\0" as *const u8 as *const libc::c_char,
                ln: b"role\0" as *const u8 as *const libc::c_char,
                nid: 400 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2931 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"policyConstraints\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Policy Constraints\0" as *const u8 as *const libc::c_char,
                nid: 401 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2934 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"targetInformation\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 AC Targeting\0" as *const u8 as *const libc::c_char,
                nid: 402 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2937 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"noRevAvail\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 No Revocation Available\0" as *const u8
                    as *const libc::c_char,
                nid: 403 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2940 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ansi-X9-62\0" as *const u8 as *const libc::c_char,
                ln: b"ANSI X9.62\0" as *const u8 as *const libc::c_char,
                nid: 405 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2943 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime-field\0" as *const u8 as *const libc::c_char,
                ln: b"prime-field\0" as *const u8 as *const libc::c_char,
                nid: 406 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2948 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"characteristic-two-field\0" as *const u8 as *const libc::c_char,
                ln: b"characteristic-two-field\0" as *const u8 as *const libc::c_char,
                nid: 407 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2955 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ecPublicKey\0" as *const u8 as *const libc::c_char,
                ln: b"id-ecPublicKey\0" as *const u8 as *const libc::c_char,
                nid: 408 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2962 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime192v1\0" as *const u8 as *const libc::c_char,
                ln: b"prime192v1\0" as *const u8 as *const libc::c_char,
                nid: 409 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2969 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime192v2\0" as *const u8 as *const libc::c_char,
                ln: b"prime192v2\0" as *const u8 as *const libc::c_char,
                nid: 410 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2977 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime192v3\0" as *const u8 as *const libc::c_char,
                ln: b"prime192v3\0" as *const u8 as *const libc::c_char,
                nid: 411 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2985 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime239v1\0" as *const u8 as *const libc::c_char,
                ln: b"prime239v1\0" as *const u8 as *const libc::c_char,
                nid: 412 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(2993 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime239v2\0" as *const u8 as *const libc::c_char,
                ln: b"prime239v2\0" as *const u8 as *const libc::c_char,
                nid: 413 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3001 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime239v3\0" as *const u8 as *const libc::c_char,
                ln: b"prime239v3\0" as *const u8 as *const libc::c_char,
                nid: 414 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3009 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prime256v1\0" as *const u8 as *const libc::c_char,
                ln: b"prime256v1\0" as *const u8 as *const libc::c_char,
                nid: 415 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3017 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-SHA1\0" as *const u8 as *const libc::c_char,
                nid: 416 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3025 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CSPName\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft CSP Name\0" as *const u8 as *const libc::c_char,
                nid: 417 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3032 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-ecb\0" as *const u8 as *const libc::c_char,
                nid: 418 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3041 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-cbc\0" as *const u8 as *const libc::c_char,
                nid: 419 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3050 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-ofb\0" as *const u8 as *const libc::c_char,
                nid: 420 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3059 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-cfb\0" as *const u8 as *const libc::c_char,
                nid: 421 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3068 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-ecb\0" as *const u8 as *const libc::c_char,
                nid: 422 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3077 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-cbc\0" as *const u8 as *const libc::c_char,
                nid: 423 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3086 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-ofb\0" as *const u8 as *const libc::c_char,
                nid: 424 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3095 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-cfb\0" as *const u8 as *const libc::c_char,
                nid: 425 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3104 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-ecb\0" as *const u8 as *const libc::c_char,
                nid: 426 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3113 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-cbc\0" as *const u8 as *const libc::c_char,
                nid: 427 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3122 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-ofb\0" as *const u8 as *const libc::c_char,
                nid: 428 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3131 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-cfb\0" as *const u8 as *const libc::c_char,
                nid: 429 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3140 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"holdInstructionCode\0" as *const u8 as *const libc::c_char,
                ln: b"Hold Instruction Code\0" as *const u8 as *const libc::c_char,
                nid: 430 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3149 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"holdInstructionNone\0" as *const u8 as *const libc::c_char,
                ln: b"Hold Instruction None\0" as *const u8 as *const libc::c_char,
                nid: 431 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3152 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"holdInstructionCallIssuer\0" as *const u8 as *const libc::c_char,
                ln: b"Hold Instruction Call Issuer\0" as *const u8
                    as *const libc::c_char,
                nid: 432 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3159 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"holdInstructionReject\0" as *const u8 as *const libc::c_char,
                ln: b"Hold Instruction Reject\0" as *const u8 as *const libc::c_char,
                nid: 433 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3166 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"data\0" as *const u8 as *const libc::c_char,
                ln: b"data\0" as *const u8 as *const libc::c_char,
                nid: 434 as libc::c_int,
                length: 1 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3173 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pss\0" as *const u8 as *const libc::c_char,
                ln: b"pss\0" as *const u8 as *const libc::c_char,
                nid: 435 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3174 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ucl\0" as *const u8 as *const libc::c_char,
                ln: b"ucl\0" as *const u8 as *const libc::c_char,
                nid: 436 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3177 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilot\0" as *const u8 as *const libc::c_char,
                ln: b"pilot\0" as *const u8 as *const libc::c_char,
                nid: 437 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3184 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotAttributeType\0" as *const u8 as *const libc::c_char,
                ln: b"pilotAttributeType\0" as *const u8 as *const libc::c_char,
                nid: 438 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3192 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotAttributeSyntax\0" as *const u8 as *const libc::c_char,
                ln: b"pilotAttributeSyntax\0" as *const u8 as *const libc::c_char,
                nid: 439 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3201 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotObjectClass\0" as *const u8 as *const libc::c_char,
                ln: b"pilotObjectClass\0" as *const u8 as *const libc::c_char,
                nid: 440 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3210 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotGroups\0" as *const u8 as *const libc::c_char,
                ln: b"pilotGroups\0" as *const u8 as *const libc::c_char,
                nid: 441 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3219 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"iA5StringSyntax\0" as *const u8 as *const libc::c_char,
                ln: b"iA5StringSyntax\0" as *const u8 as *const libc::c_char,
                nid: 442 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3228 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"caseIgnoreIA5StringSyntax\0" as *const u8 as *const libc::c_char,
                ln: b"caseIgnoreIA5StringSyntax\0" as *const u8 as *const libc::c_char,
                nid: 443 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3238 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotObject\0" as *const u8 as *const libc::c_char,
                ln: b"pilotObject\0" as *const u8 as *const libc::c_char,
                nid: 444 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3248 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotPerson\0" as *const u8 as *const libc::c_char,
                ln: b"pilotPerson\0" as *const u8 as *const libc::c_char,
                nid: 445 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3258 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"account\0" as *const u8 as *const libc::c_char,
                ln: b"account\0" as *const u8 as *const libc::c_char,
                nid: 446 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3268 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"document\0" as *const u8 as *const libc::c_char,
                ln: b"document\0" as *const u8 as *const libc::c_char,
                nid: 447 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3278 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"room\0" as *const u8 as *const libc::c_char,
                ln: b"room\0" as *const u8 as *const libc::c_char,
                nid: 448 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3288 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentSeries\0" as *const u8 as *const libc::c_char,
                ln: b"documentSeries\0" as *const u8 as *const libc::c_char,
                nid: 449 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3298 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"rFC822localPart\0" as *const u8 as *const libc::c_char,
                ln: b"rFC822localPart\0" as *const u8 as *const libc::c_char,
                nid: 450 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3308 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dNSDomain\0" as *const u8 as *const libc::c_char,
                ln: b"dNSDomain\0" as *const u8 as *const libc::c_char,
                nid: 451 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3318 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"domainRelatedObject\0" as *const u8 as *const libc::c_char,
                ln: b"domainRelatedObject\0" as *const u8 as *const libc::c_char,
                nid: 452 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3328 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"friendlyCountry\0" as *const u8 as *const libc::c_char,
                ln: b"friendlyCountry\0" as *const u8 as *const libc::c_char,
                nid: 453 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3338 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"simpleSecurityObject\0" as *const u8 as *const libc::c_char,
                ln: b"simpleSecurityObject\0" as *const u8 as *const libc::c_char,
                nid: 454 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3348 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotOrganization\0" as *const u8 as *const libc::c_char,
                ln: b"pilotOrganization\0" as *const u8 as *const libc::c_char,
                nid: 455 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3358 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotDSA\0" as *const u8 as *const libc::c_char,
                ln: b"pilotDSA\0" as *const u8 as *const libc::c_char,
                nid: 456 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3368 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"qualityLabelledData\0" as *const u8 as *const libc::c_char,
                ln: b"qualityLabelledData\0" as *const u8 as *const libc::c_char,
                nid: 457 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3378 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"UID\0" as *const u8 as *const libc::c_char,
                ln: b"userId\0" as *const u8 as *const libc::c_char,
                nid: 458 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3388 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"textEncodedORAddress\0" as *const u8 as *const libc::c_char,
                ln: b"textEncodedORAddress\0" as *const u8 as *const libc::c_char,
                nid: 459 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3398 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mail\0" as *const u8 as *const libc::c_char,
                ln: b"rfc822Mailbox\0" as *const u8 as *const libc::c_char,
                nid: 460 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3408 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"info\0" as *const u8 as *const libc::c_char,
                ln: b"info\0" as *const u8 as *const libc::c_char,
                nid: 461 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3418 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"favouriteDrink\0" as *const u8 as *const libc::c_char,
                ln: b"favouriteDrink\0" as *const u8 as *const libc::c_char,
                nid: 462 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3428 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"roomNumber\0" as *const u8 as *const libc::c_char,
                ln: b"roomNumber\0" as *const u8 as *const libc::c_char,
                nid: 463 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3438 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"photo\0" as *const u8 as *const libc::c_char,
                ln: b"photo\0" as *const u8 as *const libc::c_char,
                nid: 464 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3448 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"userClass\0" as *const u8 as *const libc::c_char,
                ln: b"userClass\0" as *const u8 as *const libc::c_char,
                nid: 465 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3458 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"host\0" as *const u8 as *const libc::c_char,
                ln: b"host\0" as *const u8 as *const libc::c_char,
                nid: 466 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3468 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"manager\0" as *const u8 as *const libc::c_char,
                ln: b"manager\0" as *const u8 as *const libc::c_char,
                nid: 467 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3478 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"documentIdentifier\0" as *const u8 as *const libc::c_char,
                nid: 468 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3488 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentTitle\0" as *const u8 as *const libc::c_char,
                ln: b"documentTitle\0" as *const u8 as *const libc::c_char,
                nid: 469 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3498 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentVersion\0" as *const u8 as *const libc::c_char,
                ln: b"documentVersion\0" as *const u8 as *const libc::c_char,
                nid: 470 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3508 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentAuthor\0" as *const u8 as *const libc::c_char,
                ln: b"documentAuthor\0" as *const u8 as *const libc::c_char,
                nid: 471 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3518 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentLocation\0" as *const u8 as *const libc::c_char,
                ln: b"documentLocation\0" as *const u8 as *const libc::c_char,
                nid: 472 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3528 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"homeTelephoneNumber\0" as *const u8 as *const libc::c_char,
                ln: b"homeTelephoneNumber\0" as *const u8 as *const libc::c_char,
                nid: 473 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3538 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secretary\0" as *const u8 as *const libc::c_char,
                ln: b"secretary\0" as *const u8 as *const libc::c_char,
                nid: 474 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3548 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"otherMailbox\0" as *const u8 as *const libc::c_char,
                ln: b"otherMailbox\0" as *const u8 as *const libc::c_char,
                nid: 475 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3558 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"lastModifiedTime\0" as *const u8 as *const libc::c_char,
                ln: b"lastModifiedTime\0" as *const u8 as *const libc::c_char,
                nid: 476 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3568 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"lastModifiedBy\0" as *const u8 as *const libc::c_char,
                ln: b"lastModifiedBy\0" as *const u8 as *const libc::c_char,
                nid: 477 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3578 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"aRecord\0" as *const u8 as *const libc::c_char,
                ln: b"aRecord\0" as *const u8 as *const libc::c_char,
                nid: 478 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3588 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pilotAttributeType27\0" as *const u8 as *const libc::c_char,
                ln: b"pilotAttributeType27\0" as *const u8 as *const libc::c_char,
                nid: 479 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3598 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mXRecord\0" as *const u8 as *const libc::c_char,
                ln: b"mXRecord\0" as *const u8 as *const libc::c_char,
                nid: 480 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3608 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nSRecord\0" as *const u8 as *const libc::c_char,
                ln: b"nSRecord\0" as *const u8 as *const libc::c_char,
                nid: 481 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3618 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sOARecord\0" as *const u8 as *const libc::c_char,
                ln: b"sOARecord\0" as *const u8 as *const libc::c_char,
                nid: 482 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3628 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"cNAMERecord\0" as *const u8 as *const libc::c_char,
                ln: b"cNAMERecord\0" as *const u8 as *const libc::c_char,
                nid: 483 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3638 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"associatedDomain\0" as *const u8 as *const libc::c_char,
                ln: b"associatedDomain\0" as *const u8 as *const libc::c_char,
                nid: 484 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3648 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"associatedName\0" as *const u8 as *const libc::c_char,
                ln: b"associatedName\0" as *const u8 as *const libc::c_char,
                nid: 485 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3658 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"homePostalAddress\0" as *const u8 as *const libc::c_char,
                ln: b"homePostalAddress\0" as *const u8 as *const libc::c_char,
                nid: 486 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3668 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"personalTitle\0" as *const u8 as *const libc::c_char,
                ln: b"personalTitle\0" as *const u8 as *const libc::c_char,
                nid: 487 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3678 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mobileTelephoneNumber\0" as *const u8 as *const libc::c_char,
                ln: b"mobileTelephoneNumber\0" as *const u8 as *const libc::c_char,
                nid: 488 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3688 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pagerTelephoneNumber\0" as *const u8 as *const libc::c_char,
                ln: b"pagerTelephoneNumber\0" as *const u8 as *const libc::c_char,
                nid: 489 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3698 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"friendlyCountryName\0" as *const u8 as *const libc::c_char,
                ln: b"friendlyCountryName\0" as *const u8 as *const libc::c_char,
                nid: 490 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3708 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"organizationalStatus\0" as *const u8 as *const libc::c_char,
                ln: b"organizationalStatus\0" as *const u8 as *const libc::c_char,
                nid: 491 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3718 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"janetMailbox\0" as *const u8 as *const libc::c_char,
                ln: b"janetMailbox\0" as *const u8 as *const libc::c_char,
                nid: 492 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3728 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mailPreferenceOption\0" as *const u8 as *const libc::c_char,
                ln: b"mailPreferenceOption\0" as *const u8 as *const libc::c_char,
                nid: 493 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3738 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"buildingName\0" as *const u8 as *const libc::c_char,
                ln: b"buildingName\0" as *const u8 as *const libc::c_char,
                nid: 494 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3748 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dSAQuality\0" as *const u8 as *const libc::c_char,
                ln: b"dSAQuality\0" as *const u8 as *const libc::c_char,
                nid: 495 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3758 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"singleLevelQuality\0" as *const u8 as *const libc::c_char,
                ln: b"singleLevelQuality\0" as *const u8 as *const libc::c_char,
                nid: 496 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3768 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"subtreeMinimumQuality\0" as *const u8 as *const libc::c_char,
                ln: b"subtreeMinimumQuality\0" as *const u8 as *const libc::c_char,
                nid: 497 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3778 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"subtreeMaximumQuality\0" as *const u8 as *const libc::c_char,
                ln: b"subtreeMaximumQuality\0" as *const u8 as *const libc::c_char,
                nid: 498 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3788 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"personalSignature\0" as *const u8 as *const libc::c_char,
                ln: b"personalSignature\0" as *const u8 as *const libc::c_char,
                nid: 499 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3798 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dITRedirect\0" as *const u8 as *const libc::c_char,
                ln: b"dITRedirect\0" as *const u8 as *const libc::c_char,
                nid: 500 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3808 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"audio\0" as *const u8 as *const libc::c_char,
                ln: b"audio\0" as *const u8 as *const libc::c_char,
                nid: 501 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3818 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"documentPublisher\0" as *const u8 as *const libc::c_char,
                ln: b"documentPublisher\0" as *const u8 as *const libc::c_char,
                nid: 502 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3828 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"x500UniqueIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"x500UniqueIdentifier\0" as *const u8 as *const libc::c_char,
                nid: 503 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3838 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mime-mhs\0" as *const u8 as *const libc::c_char,
                ln: b"MIME MHS\0" as *const u8 as *const libc::c_char,
                nid: 504 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3841 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mime-mhs-headings\0" as *const u8 as *const libc::c_char,
                ln: b"mime-mhs-headings\0" as *const u8 as *const libc::c_char,
                nid: 505 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3846 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"mime-mhs-bodies\0" as *const u8 as *const libc::c_char,
                ln: b"mime-mhs-bodies\0" as *const u8 as *const libc::c_char,
                nid: 506 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3852 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-hex-partial-message\0" as *const u8 as *const libc::c_char,
                ln: b"id-hex-partial-message\0" as *const u8 as *const libc::c_char,
                nid: 507 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3858 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-hex-multipart-message\0" as *const u8 as *const libc::c_char,
                ln: b"id-hex-multipart-message\0" as *const u8 as *const libc::c_char,
                nid: 508 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3865 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"generationQualifier\0" as *const u8 as *const libc::c_char,
                ln: b"generationQualifier\0" as *const u8 as *const libc::c_char,
                nid: 509 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3872 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"pseudonym\0" as *const u8 as *const libc::c_char,
                ln: b"pseudonym\0" as *const u8 as *const libc::c_char,
                nid: 510 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3875 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-set\0" as *const u8 as *const libc::c_char,
                ln: b"Secure Electronic Transactions\0" as *const u8
                    as *const libc::c_char,
                nid: 512 as libc::c_int,
                length: 2 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3878 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-ctype\0" as *const u8 as *const libc::c_char,
                ln: b"content types\0" as *const u8 as *const libc::c_char,
                nid: 513 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3880 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-msgExt\0" as *const u8 as *const libc::c_char,
                ln: b"message extensions\0" as *const u8 as *const libc::c_char,
                nid: 514 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3883 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-attr\0" as *const u8 as *const libc::c_char,
                ln: b"set-attr\0" as *const u8 as *const libc::c_char,
                nid: 515 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3886 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-policy\0" as *const u8 as *const libc::c_char,
                ln: b"set-policy\0" as *const u8 as *const libc::c_char,
                nid: 516 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3889 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-certExt\0" as *const u8 as *const libc::c_char,
                ln: b"certificate extensions\0" as *const u8 as *const libc::c_char,
                nid: 517 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3892 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand\0" as *const u8 as *const libc::c_char,
                nid: 518 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3895 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PANData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PANData\0" as *const u8 as *const libc::c_char,
                nid: 519 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3898 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PANToken\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PANToken\0" as *const u8 as *const libc::c_char,
                nid: 520 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3902 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PANOnly\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PANOnly\0" as *const u8 as *const libc::c_char,
                nid: 521 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3906 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-OIData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-OIData\0" as *const u8 as *const libc::c_char,
                nid: 522 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3910 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PI\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PI\0" as *const u8 as *const libc::c_char,
                nid: 523 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3914 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PIData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PIData\0" as *const u8 as *const libc::c_char,
                nid: 524 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3918 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PIDataUnsigned\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PIDataUnsigned\0" as *const u8 as *const libc::c_char,
                nid: 525 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3922 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-HODInput\0" as *const u8 as *const libc::c_char,
                ln: b"setct-HODInput\0" as *const u8 as *const libc::c_char,
                nid: 526 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3926 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthResBaggage\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthResBaggage\0" as *const u8 as *const libc::c_char,
                nid: 527 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3930 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevReqBaggage\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevReqBaggage\0" as *const u8 as *const libc::c_char,
                nid: 528 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3934 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevResBaggage\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevResBaggage\0" as *const u8 as *const libc::c_char,
                nid: 529 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3938 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapTokenSeq\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapTokenSeq\0" as *const u8 as *const libc::c_char,
                nid: 530 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3942 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PInitResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PInitResData\0" as *const u8 as *const libc::c_char,
                nid: 531 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3946 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PI-TBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PI-TBS\0" as *const u8 as *const libc::c_char,
                nid: 532 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3950 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PResData\0" as *const u8 as *const libc::c_char,
                nid: 533 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3954 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 534 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3958 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthResTBS\0" as *const u8 as *const libc::c_char,
                nid: 535 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3962 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthResTBSX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthResTBSX\0" as *const u8 as *const libc::c_char,
                nid: 536 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3966 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthTokenTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthTokenTBS\0" as *const u8 as *const libc::c_char,
                nid: 537 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3970 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapTokenData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapTokenData\0" as *const u8 as *const libc::c_char,
                nid: 538 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3974 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapTokenTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapTokenTBS\0" as *const u8 as *const libc::c_char,
                nid: 539 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3978 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AcqCardCodeMsg\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AcqCardCodeMsg\0" as *const u8 as *const libc::c_char,
                nid: 540 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3982 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 541 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3986 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevResData\0" as *const u8 as *const libc::c_char,
                nid: 542 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3990 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevResTBS\0" as *const u8 as *const libc::c_char,
                nid: 543 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3994 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 544 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(3998 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapReqTBSX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapReqTBSX\0" as *const u8 as *const libc::c_char,
                nid: 545 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4002 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapResData\0" as *const u8 as *const libc::c_char,
                nid: 546 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4006 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapRevReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapRevReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 547 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4010 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapRevReqTBSX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapRevReqTBSX\0" as *const u8 as *const libc::c_char,
                nid: 548 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4014 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapRevResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapRevResData\0" as *const u8 as *const libc::c_char,
                nid: 549 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4018 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 550 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4022 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredReqTBSX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredReqTBSX\0" as *const u8 as *const libc::c_char,
                nid: 551 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4026 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredResData\0" as *const u8 as *const libc::c_char,
                nid: 552 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4030 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredRevReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredRevReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 553 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4034 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredRevReqTBSX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredRevReqTBSX\0" as *const u8 as *const libc::c_char,
                nid: 554 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4038 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredRevResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredRevResData\0" as *const u8 as *const libc::c_char,
                nid: 555 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4042 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PCertReqData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PCertReqData\0" as *const u8 as *const libc::c_char,
                nid: 556 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4046 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PCertResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PCertResTBS\0" as *const u8 as *const libc::c_char,
                nid: 557 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4050 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-BatchAdminReqData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-BatchAdminReqData\0" as *const u8 as *const libc::c_char,
                nid: 558 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4054 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-BatchAdminResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-BatchAdminResData\0" as *const u8 as *const libc::c_char,
                nid: 559 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4058 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CardCInitResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CardCInitResTBS\0" as *const u8 as *const libc::c_char,
                nid: 560 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4062 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-MeAqCInitResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-MeAqCInitResTBS\0" as *const u8 as *const libc::c_char,
                nid: 561 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4066 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-RegFormResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-RegFormResTBS\0" as *const u8 as *const libc::c_char,
                nid: 562 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4070 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertReqData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertReqData\0" as *const u8 as *const libc::c_char,
                nid: 563 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4074 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 564 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4078 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertResData\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertResData\0" as *const u8 as *const libc::c_char,
                nid: 565 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4082 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertInqReqTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertInqReqTBS\0" as *const u8 as *const libc::c_char,
                nid: 566 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4086 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-ErrorTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-ErrorTBS\0" as *const u8 as *const libc::c_char,
                nid: 567 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4090 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PIDualSignedTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PIDualSignedTBE\0" as *const u8 as *const libc::c_char,
                nid: 568 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4094 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-PIUnsignedTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-PIUnsignedTBE\0" as *const u8 as *const libc::c_char,
                nid: 569 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4098 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 570 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4102 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthResTBE\0" as *const u8 as *const libc::c_char,
                nid: 571 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4106 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthResTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthResTBEX\0" as *const u8 as *const libc::c_char,
                nid: 572 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4110 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthTokenTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthTokenTBE\0" as *const u8 as *const libc::c_char,
                nid: 573 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4114 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapTokenTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapTokenTBE\0" as *const u8 as *const libc::c_char,
                nid: 574 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4118 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapTokenTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapTokenTBEX\0" as *const u8 as *const libc::c_char,
                nid: 575 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4122 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AcqCardCodeMsgTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AcqCardCodeMsgTBE\0" as *const u8 as *const libc::c_char,
                nid: 576 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4126 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 577 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4130 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevResTBE\0" as *const u8 as *const libc::c_char,
                nid: 578 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4134 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-AuthRevResTBEB\0" as *const u8 as *const libc::c_char,
                ln: b"setct-AuthRevResTBEB\0" as *const u8 as *const libc::c_char,
                nid: 579 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4138 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 580 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4142 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapReqTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapReqTBEX\0" as *const u8 as *const libc::c_char,
                nid: 581 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4146 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapResTBE\0" as *const u8 as *const libc::c_char,
                nid: 582 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4150 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapRevReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapRevReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 583 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4154 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapRevReqTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapRevReqTBEX\0" as *const u8 as *const libc::c_char,
                nid: 584 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4158 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CapRevResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CapRevResTBE\0" as *const u8 as *const libc::c_char,
                nid: 585 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4162 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 586 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4166 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredReqTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredReqTBEX\0" as *const u8 as *const libc::c_char,
                nid: 587 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4170 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredResTBE\0" as *const u8 as *const libc::c_char,
                nid: 588 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4174 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredRevReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredRevReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 589 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4178 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredRevReqTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredRevReqTBEX\0" as *const u8 as *const libc::c_char,
                nid: 590 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4182 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CredRevResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CredRevResTBE\0" as *const u8 as *const libc::c_char,
                nid: 591 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4186 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-BatchAdminReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-BatchAdminReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 592 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4190 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-BatchAdminResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-BatchAdminResTBE\0" as *const u8 as *const libc::c_char,
                nid: 593 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4194 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-RegFormReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-RegFormReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 594 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4198 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertReqTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertReqTBE\0" as *const u8 as *const libc::c_char,
                nid: 595 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4202 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertReqTBEX\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertReqTBEX\0" as *const u8 as *const libc::c_char,
                nid: 596 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4206 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CertResTBE\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CertResTBE\0" as *const u8 as *const libc::c_char,
                nid: 597 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4210 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CRLNotificationTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CRLNotificationTBS\0" as *const u8 as *const libc::c_char,
                nid: 598 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4214 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-CRLNotificationResTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-CRLNotificationResTBS\0" as *const u8 as *const libc::c_char,
                nid: 599 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4218 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setct-BCIDistributionTBS\0" as *const u8 as *const libc::c_char,
                ln: b"setct-BCIDistributionTBS\0" as *const u8 as *const libc::c_char,
                nid: 600 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4222 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setext-genCrypt\0" as *const u8 as *const libc::c_char,
                ln: b"generic cryptogram\0" as *const u8 as *const libc::c_char,
                nid: 601 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4226 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setext-miAuth\0" as *const u8 as *const libc::c_char,
                ln: b"merchant initiated auth\0" as *const u8 as *const libc::c_char,
                nid: 602 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4230 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setext-pinSecure\0" as *const u8 as *const libc::c_char,
                ln: b"setext-pinSecure\0" as *const u8 as *const libc::c_char,
                nid: 603 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4234 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setext-pinAny\0" as *const u8 as *const libc::c_char,
                ln: b"setext-pinAny\0" as *const u8 as *const libc::c_char,
                nid: 604 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4238 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setext-track2\0" as *const u8 as *const libc::c_char,
                ln: b"setext-track2\0" as *const u8 as *const libc::c_char,
                nid: 605 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4242 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setext-cv\0" as *const u8 as *const libc::c_char,
                ln: b"additional verification\0" as *const u8 as *const libc::c_char,
                nid: 606 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4246 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-policy-root\0" as *const u8 as *const libc::c_char,
                ln: b"set-policy-root\0" as *const u8 as *const libc::c_char,
                nid: 607 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4250 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-hashedRoot\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-hashedRoot\0" as *const u8 as *const libc::c_char,
                nid: 608 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4254 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-certType\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-certType\0" as *const u8 as *const libc::c_char,
                nid: 609 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4258 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-merchData\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-merchData\0" as *const u8 as *const libc::c_char,
                nid: 610 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4262 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-cCertRequired\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-cCertRequired\0" as *const u8 as *const libc::c_char,
                nid: 611 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4266 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-tunneling\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-tunneling\0" as *const u8 as *const libc::c_char,
                nid: 612 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4270 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-setExt\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-setExt\0" as *const u8 as *const libc::c_char,
                nid: 613 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4274 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-setQualf\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-setQualf\0" as *const u8 as *const libc::c_char,
                nid: 614 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4278 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-PGWYcapabilities\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-PGWYcapabilities\0" as *const u8 as *const libc::c_char,
                nid: 615 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4282 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-TokenIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-TokenIdentifier\0" as *const u8 as *const libc::c_char,
                nid: 616 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4286 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-Track2Data\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-Track2Data\0" as *const u8 as *const libc::c_char,
                nid: 617 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4290 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-TokenType\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-TokenType\0" as *const u8 as *const libc::c_char,
                nid: 618 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4294 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setCext-IssuerCapabilities\0" as *const u8 as *const libc::c_char,
                ln: b"setCext-IssuerCapabilities\0" as *const u8 as *const libc::c_char,
                nid: 619 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4298 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-Cert\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-Cert\0" as *const u8 as *const libc::c_char,
                nid: 620 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4302 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-PGWYcap\0" as *const u8 as *const libc::c_char,
                ln: b"payment gateway capabilities\0" as *const u8
                    as *const libc::c_char,
                nid: 621 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4306 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-TokenType\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-TokenType\0" as *const u8 as *const libc::c_char,
                nid: 622 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4310 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-IssCap\0" as *const u8 as *const libc::c_char,
                ln: b"issuer capabilities\0" as *const u8 as *const libc::c_char,
                nid: 623 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4314 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-rootKeyThumb\0" as *const u8 as *const libc::c_char,
                ln: b"set-rootKeyThumb\0" as *const u8 as *const libc::c_char,
                nid: 624 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4318 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-addPolicy\0" as *const u8 as *const libc::c_char,
                ln: b"set-addPolicy\0" as *const u8 as *const libc::c_char,
                nid: 625 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4323 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-Token-EMV\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-Token-EMV\0" as *const u8 as *const libc::c_char,
                nid: 626 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4328 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-Token-B0Prime\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-Token-B0Prime\0" as *const u8 as *const libc::c_char,
                nid: 627 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4333 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-IssCap-CVM\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-IssCap-CVM\0" as *const u8 as *const libc::c_char,
                nid: 628 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4338 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-IssCap-T2\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-IssCap-T2\0" as *const u8 as *const libc::c_char,
                nid: 629 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4343 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-IssCap-Sig\0" as *const u8 as *const libc::c_char,
                ln: b"setAttr-IssCap-Sig\0" as *const u8 as *const libc::c_char,
                nid: 630 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4348 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-GenCryptgrm\0" as *const u8 as *const libc::c_char,
                ln: b"generate cryptogram\0" as *const u8 as *const libc::c_char,
                nid: 631 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4353 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-T2Enc\0" as *const u8 as *const libc::c_char,
                ln: b"encrypted track 2\0" as *const u8 as *const libc::c_char,
                nid: 632 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4359 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-T2cleartxt\0" as *const u8 as *const libc::c_char,
                ln: b"cleartext track 2\0" as *const u8 as *const libc::c_char,
                nid: 633 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4365 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-TokICCsig\0" as *const u8 as *const libc::c_char,
                ln: b"ICC or token signature\0" as *const u8 as *const libc::c_char,
                nid: 634 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4371 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"setAttr-SecDevSig\0" as *const u8 as *const libc::c_char,
                ln: b"secure device signature\0" as *const u8 as *const libc::c_char,
                nid: 635 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4377 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-IATA-ATA\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-IATA-ATA\0" as *const u8 as *const libc::c_char,
                nid: 636 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4383 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-Diners\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-Diners\0" as *const u8 as *const libc::c_char,
                nid: 637 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4387 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-AmericanExpress\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-AmericanExpress\0" as *const u8 as *const libc::c_char,
                nid: 638 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4391 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-JCB\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-JCB\0" as *const u8 as *const libc::c_char,
                nid: 639 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4395 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-Visa\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-Visa\0" as *const u8 as *const libc::c_char,
                nid: 640 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4399 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-MasterCard\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-MasterCard\0" as *const u8 as *const libc::c_char,
                nid: 641 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4403 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"set-brand-Novus\0" as *const u8 as *const libc::c_char,
                ln: b"set-brand-Novus\0" as *const u8 as *const libc::c_char,
                nid: 642 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4407 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-CDMF\0" as *const u8 as *const libc::c_char,
                ln: b"des-cdmf\0" as *const u8 as *const libc::c_char,
                nid: 643 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4412 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"rsaOAEPEncryptionSET\0" as *const u8 as *const libc::c_char,
                ln: b"rsaOAEPEncryptionSET\0" as *const u8 as *const libc::c_char,
                nid: 644 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4420 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ITU-T\0" as *const u8 as *const libc::c_char,
                ln: b"itu-t\0" as *const u8 as *const libc::c_char,
                nid: 645 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"JOINT-ISO-ITU-T\0" as *const u8 as *const libc::c_char,
                ln: b"joint-iso-itu-t\0" as *const u8 as *const libc::c_char,
                nid: 646 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"international-organizations\0" as *const u8 as *const libc::c_char,
                ln: b"International Organizations\0" as *const u8 as *const libc::c_char,
                nid: 647 as libc::c_int,
                length: 1 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4429 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msSmartcardLogin\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Smartcardlogin\0" as *const u8 as *const libc::c_char,
                nid: 648 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4430 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"msUPN\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Universal Principal Name\0" as *const u8
                    as *const libc::c_char,
                nid: 649 as libc::c_int,
                length: 10 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4440 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 650 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 651 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 652 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 653 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 654 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 655 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"des-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 656 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"des-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 657 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE3-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede3-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 658 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DES-EDE3-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"des-ede3-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 659 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"street\0" as *const u8 as *const libc::c_char,
                ln: b"streetAddress\0" as *const u8 as *const libc::c_char,
                nid: 660 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4450 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"postalCode\0" as *const u8 as *const libc::c_char,
                ln: b"postalCode\0" as *const u8 as *const libc::c_char,
                nid: 661 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4453 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ppl\0" as *const u8 as *const libc::c_char,
                ln: b"id-ppl\0" as *const u8 as *const libc::c_char,
                nid: 662 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4456 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"proxyCertInfo\0" as *const u8 as *const libc::c_char,
                ln: b"Proxy Certificate Information\0" as *const u8
                    as *const libc::c_char,
                nid: 663 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4463 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ppl-anyLanguage\0" as *const u8 as *const libc::c_char,
                ln: b"Any language\0" as *const u8 as *const libc::c_char,
                nid: 664 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4471 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ppl-inheritAll\0" as *const u8 as *const libc::c_char,
                ln: b"Inherit all\0" as *const u8 as *const libc::c_char,
                nid: 665 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4479 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"nameConstraints\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Name Constraints\0" as *const u8 as *const libc::c_char,
                nid: 666 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4487 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ppl-independent\0" as *const u8 as *const libc::c_char,
                ln: b"Independent\0" as *const u8 as *const libc::c_char,
                nid: 667 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4490 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA256\0" as *const u8 as *const libc::c_char,
                ln: b"sha256WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 668 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4498 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA384\0" as *const u8 as *const libc::c_char,
                ln: b"sha384WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 669 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4507 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA512\0" as *const u8 as *const libc::c_char,
                ln: b"sha512WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 670 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4516 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSA-SHA224\0" as *const u8 as *const libc::c_char,
                ln: b"sha224WithRSAEncryption\0" as *const u8 as *const libc::c_char,
                nid: 671 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4525 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA256\0" as *const u8 as *const libc::c_char,
                ln: b"sha256\0" as *const u8 as *const libc::c_char,
                nid: 672 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4534 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA384\0" as *const u8 as *const libc::c_char,
                ln: b"sha384\0" as *const u8 as *const libc::c_char,
                nid: 673 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4543 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA512\0" as *const u8 as *const libc::c_char,
                ln: b"sha512\0" as *const u8 as *const libc::c_char,
                nid: 674 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4552 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA224\0" as *const u8 as *const libc::c_char,
                ln: b"sha224\0" as *const u8 as *const libc::c_char,
                nid: 675 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4561 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"identified-organization\0" as *const u8 as *const libc::c_char,
                ln: b"identified-organization\0" as *const u8 as *const libc::c_char,
                nid: 676 as libc::c_int,
                length: 1 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4570 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"certicom-arc\0" as *const u8 as *const libc::c_char,
                ln: b"certicom-arc\0" as *const u8 as *const libc::c_char,
                nid: 677 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4571 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap\0" as *const u8 as *const libc::c_char,
                ln: b"wap\0" as *const u8 as *const libc::c_char,
                nid: 678 as libc::c_int,
                length: 2 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4574 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg\0" as *const u8 as *const libc::c_char,
                nid: 679 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4576 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-characteristic-two-basis\0" as *const u8 as *const libc::c_char,
                ln: b"id-characteristic-two-basis\0" as *const u8 as *const libc::c_char,
                nid: 680 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4579 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"onBasis\0" as *const u8 as *const libc::c_char,
                ln: b"onBasis\0" as *const u8 as *const libc::c_char,
                nid: 681 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4587 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"tpBasis\0" as *const u8 as *const libc::c_char,
                ln: b"tpBasis\0" as *const u8 as *const libc::c_char,
                nid: 682 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4596 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ppBasis\0" as *const u8 as *const libc::c_char,
                ln: b"ppBasis\0" as *const u8 as *const libc::c_char,
                nid: 683 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4605 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb163v1\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb163v1\0" as *const u8 as *const libc::c_char,
                nid: 684 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4614 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb163v2\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb163v2\0" as *const u8 as *const libc::c_char,
                nid: 685 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4622 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb163v3\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb163v3\0" as *const u8 as *const libc::c_char,
                nid: 686 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4630 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb176v1\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb176v1\0" as *const u8 as *const libc::c_char,
                nid: 687 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4638 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb191v1\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb191v1\0" as *const u8 as *const libc::c_char,
                nid: 688 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4646 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb191v2\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb191v2\0" as *const u8 as *const libc::c_char,
                nid: 689 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4654 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb191v3\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb191v3\0" as *const u8 as *const libc::c_char,
                nid: 690 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4662 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2onb191v4\0" as *const u8 as *const libc::c_char,
                ln: b"c2onb191v4\0" as *const u8 as *const libc::c_char,
                nid: 691 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4670 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2onb191v5\0" as *const u8 as *const libc::c_char,
                ln: b"c2onb191v5\0" as *const u8 as *const libc::c_char,
                nid: 692 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4678 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb208w1\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb208w1\0" as *const u8 as *const libc::c_char,
                nid: 693 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4686 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb239v1\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb239v1\0" as *const u8 as *const libc::c_char,
                nid: 694 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4694 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb239v2\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb239v2\0" as *const u8 as *const libc::c_char,
                nid: 695 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4702 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb239v3\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb239v3\0" as *const u8 as *const libc::c_char,
                nid: 696 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4710 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2onb239v4\0" as *const u8 as *const libc::c_char,
                ln: b"c2onb239v4\0" as *const u8 as *const libc::c_char,
                nid: 697 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4718 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2onb239v5\0" as *const u8 as *const libc::c_char,
                ln: b"c2onb239v5\0" as *const u8 as *const libc::c_char,
                nid: 698 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4726 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb272w1\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb272w1\0" as *const u8 as *const libc::c_char,
                nid: 699 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4734 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb304w1\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb304w1\0" as *const u8 as *const libc::c_char,
                nid: 700 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4742 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb359v1\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb359v1\0" as *const u8 as *const libc::c_char,
                nid: 701 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4750 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2pnb368w1\0" as *const u8 as *const libc::c_char,
                ln: b"c2pnb368w1\0" as *const u8 as *const libc::c_char,
                nid: 702 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4758 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"c2tnb431r1\0" as *const u8 as *const libc::c_char,
                ln: b"c2tnb431r1\0" as *const u8 as *const libc::c_char,
                nid: 703 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4766 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp112r1\0" as *const u8 as *const libc::c_char,
                ln: b"secp112r1\0" as *const u8 as *const libc::c_char,
                nid: 704 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4774 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp112r2\0" as *const u8 as *const libc::c_char,
                ln: b"secp112r2\0" as *const u8 as *const libc::c_char,
                nid: 705 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4779 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp128r1\0" as *const u8 as *const libc::c_char,
                ln: b"secp128r1\0" as *const u8 as *const libc::c_char,
                nid: 706 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4784 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp128r2\0" as *const u8 as *const libc::c_char,
                ln: b"secp128r2\0" as *const u8 as *const libc::c_char,
                nid: 707 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4789 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp160k1\0" as *const u8 as *const libc::c_char,
                ln: b"secp160k1\0" as *const u8 as *const libc::c_char,
                nid: 708 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4794 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp160r1\0" as *const u8 as *const libc::c_char,
                ln: b"secp160r1\0" as *const u8 as *const libc::c_char,
                nid: 709 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4799 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp160r2\0" as *const u8 as *const libc::c_char,
                ln: b"secp160r2\0" as *const u8 as *const libc::c_char,
                nid: 710 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4804 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp192k1\0" as *const u8 as *const libc::c_char,
                ln: b"secp192k1\0" as *const u8 as *const libc::c_char,
                nid: 711 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4809 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp224k1\0" as *const u8 as *const libc::c_char,
                ln: b"secp224k1\0" as *const u8 as *const libc::c_char,
                nid: 712 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4814 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp224r1\0" as *const u8 as *const libc::c_char,
                ln: b"secp224r1\0" as *const u8 as *const libc::c_char,
                nid: 713 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4819 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp256k1\0" as *const u8 as *const libc::c_char,
                ln: b"secp256k1\0" as *const u8 as *const libc::c_char,
                nid: 714 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4824 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp384r1\0" as *const u8 as *const libc::c_char,
                ln: b"secp384r1\0" as *const u8 as *const libc::c_char,
                nid: 715 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4829 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"secp521r1\0" as *const u8 as *const libc::c_char,
                ln: b"secp521r1\0" as *const u8 as *const libc::c_char,
                nid: 716 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4834 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect113r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect113r1\0" as *const u8 as *const libc::c_char,
                nid: 717 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4839 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect113r2\0" as *const u8 as *const libc::c_char,
                ln: b"sect113r2\0" as *const u8 as *const libc::c_char,
                nid: 718 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4844 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect131r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect131r1\0" as *const u8 as *const libc::c_char,
                nid: 719 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4849 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect131r2\0" as *const u8 as *const libc::c_char,
                ln: b"sect131r2\0" as *const u8 as *const libc::c_char,
                nid: 720 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4854 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect163k1\0" as *const u8 as *const libc::c_char,
                ln: b"sect163k1\0" as *const u8 as *const libc::c_char,
                nid: 721 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4859 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect163r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect163r1\0" as *const u8 as *const libc::c_char,
                nid: 722 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4864 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect163r2\0" as *const u8 as *const libc::c_char,
                ln: b"sect163r2\0" as *const u8 as *const libc::c_char,
                nid: 723 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4869 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect193r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect193r1\0" as *const u8 as *const libc::c_char,
                nid: 724 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4874 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect193r2\0" as *const u8 as *const libc::c_char,
                ln: b"sect193r2\0" as *const u8 as *const libc::c_char,
                nid: 725 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4879 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect233k1\0" as *const u8 as *const libc::c_char,
                ln: b"sect233k1\0" as *const u8 as *const libc::c_char,
                nid: 726 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4884 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect233r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect233r1\0" as *const u8 as *const libc::c_char,
                nid: 727 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4889 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect239k1\0" as *const u8 as *const libc::c_char,
                ln: b"sect239k1\0" as *const u8 as *const libc::c_char,
                nid: 728 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4894 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect283k1\0" as *const u8 as *const libc::c_char,
                ln: b"sect283k1\0" as *const u8 as *const libc::c_char,
                nid: 729 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4899 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect283r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect283r1\0" as *const u8 as *const libc::c_char,
                nid: 730 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4904 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect409k1\0" as *const u8 as *const libc::c_char,
                ln: b"sect409k1\0" as *const u8 as *const libc::c_char,
                nid: 731 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4909 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect409r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect409r1\0" as *const u8 as *const libc::c_char,
                nid: 732 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4914 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect571k1\0" as *const u8 as *const libc::c_char,
                ln: b"sect571k1\0" as *const u8 as *const libc::c_char,
                nid: 733 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4919 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"sect571r1\0" as *const u8 as *const libc::c_char,
                ln: b"sect571r1\0" as *const u8 as *const libc::c_char,
                nid: 734 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4924 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls1\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls1\0" as *const u8 as *const libc::c_char,
                nid: 735 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4929 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls3\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls3\0" as *const u8 as *const libc::c_char,
                nid: 736 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4934 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls4\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls4\0" as *const u8 as *const libc::c_char,
                nid: 737 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4939 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls5\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls5\0" as *const u8 as *const libc::c_char,
                nid: 738 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4944 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls6\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls6\0" as *const u8 as *const libc::c_char,
                nid: 739 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4949 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls7\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls7\0" as *const u8 as *const libc::c_char,
                nid: 740 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4954 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls8\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls8\0" as *const u8 as *const libc::c_char,
                nid: 741 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4959 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls9\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls9\0" as *const u8 as *const libc::c_char,
                nid: 742 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4964 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls10\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls10\0" as *const u8 as *const libc::c_char,
                nid: 743 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4969 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls11\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls11\0" as *const u8 as *const libc::c_char,
                nid: 744 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4974 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"wap-wsg-idm-ecid-wtls12\0" as *const u8 as *const libc::c_char,
                ln: b"wap-wsg-idm-ecid-wtls12\0" as *const u8 as *const libc::c_char,
                nid: 745 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4979 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"anyPolicy\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Any Policy\0" as *const u8 as *const libc::c_char,
                nid: 746 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4984 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"policyMappings\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Policy Mappings\0" as *const u8 as *const libc::c_char,
                nid: 747 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4988 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"inhibitAnyPolicy\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Inhibit Any Policy\0" as *const u8 as *const libc::c_char,
                nid: 748 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4991 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"Oakley-EC2N-3\0" as *const u8 as *const libc::c_char,
                ln: b"ipsec3\0" as *const u8 as *const libc::c_char,
                nid: 749 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"Oakley-EC2N-4\0" as *const u8 as *const libc::c_char,
                ln: b"ipsec4\0" as *const u8 as *const libc::c_char,
                nid: 750 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-128-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-128-cbc\0" as *const u8 as *const libc::c_char,
                nid: 751 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(4994 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-192-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-192-cbc\0" as *const u8 as *const libc::c_char,
                nid: 752 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5005 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-256-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-256-cbc\0" as *const u8 as *const libc::c_char,
                nid: 753 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5016 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-128-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-128-ecb\0" as *const u8 as *const libc::c_char,
                nid: 754 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5027 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-192-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-192-ecb\0" as *const u8 as *const libc::c_char,
                nid: 755 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5035 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-256-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-256-ecb\0" as *const u8 as *const libc::c_char,
                nid: 756 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5043 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-128-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-128-cfb\0" as *const u8 as *const libc::c_char,
                nid: 757 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5051 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-192-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-192-cfb\0" as *const u8 as *const libc::c_char,
                nid: 758 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5059 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-256-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-256-cfb\0" as *const u8 as *const libc::c_char,
                nid: 759 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5067 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-128-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-128-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 760 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-192-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-192-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 761 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-256-CFB1\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-256-cfb1\0" as *const u8 as *const libc::c_char,
                nid: 762 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-128-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-128-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 763 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-192-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-192-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 764 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-256-CFB8\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-256-cfb8\0" as *const u8 as *const libc::c_char,
                nid: 765 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-128-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-128-ofb\0" as *const u8 as *const libc::c_char,
                nid: 766 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5075 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-192-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-192-ofb\0" as *const u8 as *const libc::c_char,
                nid: 767 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5083 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CAMELLIA-256-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"camellia-256-ofb\0" as *const u8 as *const libc::c_char,
                nid: 768 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5091 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"subjectDirectoryAttributes\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Subject Directory Attributes\0" as *const u8
                    as *const libc::c_char,
                nid: 769 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5099 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"issuingDistributionPoint\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Issuing Distribution Point\0" as *const u8
                    as *const libc::c_char,
                nid: 770 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5102 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"certificateIssuer\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Certificate Issuer\0" as *const u8 as *const libc::c_char,
                nid: 771 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5105 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KISA\0" as *const u8 as *const libc::c_char,
                ln: b"kisa\0" as *const u8 as *const libc::c_char,
                nid: 773 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5108 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SEED-ECB\0" as *const u8 as *const libc::c_char,
                ln: b"seed-ecb\0" as *const u8 as *const libc::c_char,
                nid: 776 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5114 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SEED-CBC\0" as *const u8 as *const libc::c_char,
                ln: b"seed-cbc\0" as *const u8 as *const libc::c_char,
                nid: 777 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5122 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SEED-OFB\0" as *const u8 as *const libc::c_char,
                ln: b"seed-ofb\0" as *const u8 as *const libc::c_char,
                nid: 778 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5130 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SEED-CFB\0" as *const u8 as *const libc::c_char,
                ln: b"seed-cfb\0" as *const u8 as *const libc::c_char,
                nid: 779 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5138 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"HMAC-MD5\0" as *const u8 as *const libc::c_char,
                ln: b"hmac-md5\0" as *const u8 as *const libc::c_char,
                nid: 780 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5146 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"HMAC-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"hmac-sha1\0" as *const u8 as *const libc::c_char,
                nid: 781 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5154 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-PasswordBasedMAC\0" as *const u8 as *const libc::c_char,
                ln: b"password based MAC\0" as *const u8 as *const libc::c_char,
                nid: 782 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5162 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-DHBasedMac\0" as *const u8 as *const libc::c_char,
                ln: b"Diffie-Hellman based MAC\0" as *const u8 as *const libc::c_char,
                nid: 783 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5171 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-it-suppLangTags\0" as *const u8 as *const libc::c_char,
                ln: b"id-it-suppLangTags\0" as *const u8 as *const libc::c_char,
                nid: 784 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5180 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"caRepository\0" as *const u8 as *const libc::c_char,
                ln: b"CA Repository\0" as *const u8 as *const libc::c_char,
                nid: 785 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5188 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-smime-ct-compressedData\0" as *const u8 as *const libc::c_char,
                ln: b"id-smime-ct-compressedData\0" as *const u8 as *const libc::c_char,
                nid: 786 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5196 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-ct-asciiTextWithCRLF\0" as *const u8 as *const libc::c_char,
                ln: b"id-ct-asciiTextWithCRLF\0" as *const u8 as *const libc::c_char,
                nid: 787 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5207 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes128-wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-aes128-wrap\0" as *const u8 as *const libc::c_char,
                nid: 788 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5218 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes192-wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-aes192-wrap\0" as *const u8 as *const libc::c_char,
                nid: 789 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5227 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes256-wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-aes256-wrap\0" as *const u8 as *const libc::c_char,
                nid: 790 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5236 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-Recommended\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-Recommended\0" as *const u8 as *const libc::c_char,
                nid: 791 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5245 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-Specified\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-Specified\0" as *const u8 as *const libc::c_char,
                nid: 792 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5252 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-SHA224\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-SHA224\0" as *const u8 as *const libc::c_char,
                nid: 793 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5259 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-SHA256\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-SHA256\0" as *const u8 as *const libc::c_char,
                nid: 794 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5267 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-SHA384\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-SHA384\0" as *const u8 as *const libc::c_char,
                nid: 795 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5275 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ecdsa-with-SHA512\0" as *const u8 as *const libc::c_char,
                ln: b"ecdsa-with-SHA512\0" as *const u8 as *const libc::c_char,
                nid: 796 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5283 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"hmacWithMD5\0" as *const u8 as *const libc::c_char,
                ln: b"hmacWithMD5\0" as *const u8 as *const libc::c_char,
                nid: 797 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5291 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"hmacWithSHA224\0" as *const u8 as *const libc::c_char,
                ln: b"hmacWithSHA224\0" as *const u8 as *const libc::c_char,
                nid: 798 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5299 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"hmacWithSHA256\0" as *const u8 as *const libc::c_char,
                ln: b"hmacWithSHA256\0" as *const u8 as *const libc::c_char,
                nid: 799 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5307 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"hmacWithSHA384\0" as *const u8 as *const libc::c_char,
                ln: b"hmacWithSHA384\0" as *const u8 as *const libc::c_char,
                nid: 800 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5315 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"hmacWithSHA512\0" as *const u8 as *const libc::c_char,
                ln: b"hmacWithSHA512\0" as *const u8 as *const libc::c_char,
                nid: 801 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5323 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dsa_with_SHA224\0" as *const u8 as *const libc::c_char,
                ln: b"dsa_with_SHA224\0" as *const u8 as *const libc::c_char,
                nid: 802 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5331 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dsa_with_SHA256\0" as *const u8 as *const libc::c_char,
                ln: b"dsa_with_SHA256\0" as *const u8 as *const libc::c_char,
                nid: 803 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5340 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"whirlpool\0" as *const u8 as *const libc::c_char,
                ln: b"whirlpool\0" as *const u8 as *const libc::c_char,
                nid: 804 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5349 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"cryptopro\0" as *const u8 as *const libc::c_char,
                ln: b"cryptopro\0" as *const u8 as *const libc::c_char,
                nid: 805 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5355 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"cryptocom\0" as *const u8 as *const libc::c_char,
                ln: b"cryptocom\0" as *const u8 as *const libc::c_char,
                nid: 806 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5360 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3411-94-with-GostR3410-2001\0" as *const u8
                    as *const libc::c_char,
                ln: b"GOST R 34.11-94 with GOST R 34.10-2001\0" as *const u8
                    as *const libc::c_char,
                nid: 807 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5365 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3411-94-with-GostR3410-94\0" as *const u8
                    as *const libc::c_char,
                ln: b"GOST R 34.11-94 with GOST R 34.10-94\0" as *const u8
                    as *const libc::c_char,
                nid: 808 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5371 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"md_gost94\0" as *const u8 as *const libc::c_char,
                ln: b"GOST R 34.11-94\0" as *const u8 as *const libc::c_char,
                nid: 809 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5377 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-HMACGostR3411-94\0" as *const u8 as *const libc::c_char,
                ln: b"HMAC GOST 34.11-94\0" as *const u8 as *const libc::c_char,
                nid: 810 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5383 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost2001\0" as *const u8 as *const libc::c_char,
                ln: b"GOST R 34.10-2001\0" as *const u8 as *const libc::c_char,
                nid: 811 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5389 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost94\0" as *const u8 as *const libc::c_char,
                ln: b"GOST R 34.10-94\0" as *const u8 as *const libc::c_char,
                nid: 812 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5395 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost89\0" as *const u8 as *const libc::c_char,
                ln: b"GOST 28147-89\0" as *const u8 as *const libc::c_char,
                nid: 813 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5401 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost89-cnt\0" as *const u8 as *const libc::c_char,
                ln: b"gost89-cnt\0" as *const u8 as *const libc::c_char,
                nid: 814 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost-mac\0" as *const u8 as *const libc::c_char,
                ln: b"GOST 28147-89 MAC\0" as *const u8 as *const libc::c_char,
                nid: 815 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5407 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"prf-gostr3411-94\0" as *const u8 as *const libc::c_char,
                ln: b"GOST R 34.11-94 PRF\0" as *const u8 as *const libc::c_char,
                nid: 816 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5413 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001DH\0" as *const u8 as *const libc::c_char,
                ln: b"GOST R 34.10-2001 DH\0" as *const u8 as *const libc::c_char,
                nid: 817 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5419 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94DH\0" as *const u8 as *const libc::c_char,
                ln: b"GOST R 34.10-94 DH\0" as *const u8 as *const libc::c_char,
                nid: 818 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5425 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-KeyMeshing\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-KeyMeshing\0" as *const u8
                    as *const libc::c_char,
                nid: 819 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5431 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-None-KeyMeshing\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-None-KeyMeshing\0" as *const u8
                    as *const libc::c_char,
                nid: 820 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5438 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3411-94-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3411-94-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 821 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5445 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3411-94-CryptoProParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3411-94-CryptoProParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 822 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5452 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 823 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5459 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-A-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-A-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 824 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5466 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-B-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-B-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 825 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5473 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-C-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-C-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 826 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5480 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-D-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-D-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 827 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5487 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 828 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5494 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 829 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5501 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-CryptoPro-RIC-1-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-Gost28147-89-CryptoPro-RIC-1-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 830 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5508 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 831 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5515 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-A-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-A-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 832 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5522 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-B-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-B-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 833 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5529 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-C-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-C-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 834 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5536 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-D-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-D-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 835 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5543 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-XchA-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-XchA-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 836 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5550 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-XchB-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-XchB-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 837 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5557 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-CryptoPro-XchC-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-94-CryptoPro-XchC-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 838 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5564 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-2001-TestParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 839 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5571 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-CryptoPro-A-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-2001-CryptoPro-A-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 840 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5578 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-CryptoPro-B-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-2001-CryptoPro-B-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 841 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5585 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-CryptoPro-C-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-2001-CryptoPro-C-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 842 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5592 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-CryptoPro-XchA-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-2001-CryptoPro-XchA-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 843 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5599 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-CryptoPro-XchB-ParamSet\0" as *const u8
                    as *const libc::c_char,
                ln: b"id-GostR3410-2001-CryptoPro-XchB-ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 844 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5606 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-a\0" as *const u8 as *const libc::c_char,
                ln: b"id-GostR3410-94-a\0" as *const u8 as *const libc::c_char,
                nid: 845 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5613 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-aBis\0" as *const u8 as *const libc::c_char,
                ln: b"id-GostR3410-94-aBis\0" as *const u8 as *const libc::c_char,
                nid: 846 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5620 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-b\0" as *const u8 as *const libc::c_char,
                ln: b"id-GostR3410-94-b\0" as *const u8 as *const libc::c_char,
                nid: 847 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5627 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-94-bBis\0" as *const u8 as *const libc::c_char,
                ln: b"id-GostR3410-94-bBis\0" as *const u8 as *const libc::c_char,
                nid: 848 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5634 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-Gost28147-89-cc\0" as *const u8 as *const libc::c_char,
                ln: b"GOST 28147-89 Cryptocom ParamSet\0" as *const u8
                    as *const libc::c_char,
                nid: 849 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5641 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost94cc\0" as *const u8 as *const libc::c_char,
                ln: b"GOST 34.10-94 Cryptocom\0" as *const u8 as *const libc::c_char,
                nid: 850 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5649 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"gost2001cc\0" as *const u8 as *const libc::c_char,
                ln: b"GOST 34.10-2001 Cryptocom\0" as *const u8 as *const libc::c_char,
                nid: 851 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5657 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3411-94-with-GostR3410-94-cc\0" as *const u8
                    as *const libc::c_char,
                ln: b"GOST R 34.11-94 with GOST R 34.10-94 Cryptocom\0" as *const u8
                    as *const libc::c_char,
                nid: 852 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5665 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3411-94-with-GostR3410-2001-cc\0" as *const u8
                    as *const libc::c_char,
                ln: b"GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom\0" as *const u8
                    as *const libc::c_char,
                nid: 853 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5673 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-GostR3410-2001-ParamSet-cc\0" as *const u8
                    as *const libc::c_char,
                ln: b"GOST R 3410-2001 Parameter Set Cryptocom\0" as *const u8
                    as *const libc::c_char,
                nid: 854 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5681 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"HMAC\0" as *const u8 as *const libc::c_char,
                ln: b"hmac\0" as *const u8 as *const libc::c_char,
                nid: 855 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"LocalKeySet\0" as *const u8 as *const libc::c_char,
                ln: b"Microsoft Local Key set\0" as *const u8 as *const libc::c_char,
                nid: 856 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5689 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"freshestCRL\0" as *const u8 as *const libc::c_char,
                ln: b"X509v3 Freshest CRL\0" as *const u8 as *const libc::c_char,
                nid: 857 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5698 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-on-permanentIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"Permanent Identifier\0" as *const u8 as *const libc::c_char,
                nid: 858 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5701 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"searchGuide\0" as *const u8 as *const libc::c_char,
                ln: b"searchGuide\0" as *const u8 as *const libc::c_char,
                nid: 859 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5709 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"businessCategory\0" as *const u8 as *const libc::c_char,
                ln: b"businessCategory\0" as *const u8 as *const libc::c_char,
                nid: 860 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5712 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"postalAddress\0" as *const u8 as *const libc::c_char,
                ln: b"postalAddress\0" as *const u8 as *const libc::c_char,
                nid: 861 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5715 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"postOfficeBox\0" as *const u8 as *const libc::c_char,
                ln: b"postOfficeBox\0" as *const u8 as *const libc::c_char,
                nid: 862 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5718 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"physicalDeliveryOfficeName\0" as *const u8 as *const libc::c_char,
                ln: b"physicalDeliveryOfficeName\0" as *const u8 as *const libc::c_char,
                nid: 863 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5721 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"telephoneNumber\0" as *const u8 as *const libc::c_char,
                ln: b"telephoneNumber\0" as *const u8 as *const libc::c_char,
                nid: 864 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5724 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"telexNumber\0" as *const u8 as *const libc::c_char,
                ln: b"telexNumber\0" as *const u8 as *const libc::c_char,
                nid: 865 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5727 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"teletexTerminalIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"teletexTerminalIdentifier\0" as *const u8 as *const libc::c_char,
                nid: 866 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5730 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"facsimileTelephoneNumber\0" as *const u8 as *const libc::c_char,
                ln: b"facsimileTelephoneNumber\0" as *const u8 as *const libc::c_char,
                nid: 867 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5733 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"x121Address\0" as *const u8 as *const libc::c_char,
                ln: b"x121Address\0" as *const u8 as *const libc::c_char,
                nid: 868 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5736 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"internationaliSDNNumber\0" as *const u8 as *const libc::c_char,
                ln: b"internationaliSDNNumber\0" as *const u8 as *const libc::c_char,
                nid: 869 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5739 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"registeredAddress\0" as *const u8 as *const libc::c_char,
                ln: b"registeredAddress\0" as *const u8 as *const libc::c_char,
                nid: 870 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5742 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"destinationIndicator\0" as *const u8 as *const libc::c_char,
                ln: b"destinationIndicator\0" as *const u8 as *const libc::c_char,
                nid: 871 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5745 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"preferredDeliveryMethod\0" as *const u8 as *const libc::c_char,
                ln: b"preferredDeliveryMethod\0" as *const u8 as *const libc::c_char,
                nid: 872 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5748 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"presentationAddress\0" as *const u8 as *const libc::c_char,
                ln: b"presentationAddress\0" as *const u8 as *const libc::c_char,
                nid: 873 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5751 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"supportedApplicationContext\0" as *const u8 as *const libc::c_char,
                ln: b"supportedApplicationContext\0" as *const u8 as *const libc::c_char,
                nid: 874 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5754 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"member\0" as *const u8 as *const libc::c_char,
                ln: b"member\0" as *const u8 as *const libc::c_char,
                nid: 875 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5757 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"owner\0" as *const u8 as *const libc::c_char,
                ln: b"owner\0" as *const u8 as *const libc::c_char,
                nid: 876 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5760 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"roleOccupant\0" as *const u8 as *const libc::c_char,
                ln: b"roleOccupant\0" as *const u8 as *const libc::c_char,
                nid: 877 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5763 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"seeAlso\0" as *const u8 as *const libc::c_char,
                ln: b"seeAlso\0" as *const u8 as *const libc::c_char,
                nid: 878 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5766 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"userPassword\0" as *const u8 as *const libc::c_char,
                ln: b"userPassword\0" as *const u8 as *const libc::c_char,
                nid: 879 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5769 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"userCertificate\0" as *const u8 as *const libc::c_char,
                ln: b"userCertificate\0" as *const u8 as *const libc::c_char,
                nid: 880 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5772 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"cACertificate\0" as *const u8 as *const libc::c_char,
                ln: b"cACertificate\0" as *const u8 as *const libc::c_char,
                nid: 881 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5775 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"authorityRevocationList\0" as *const u8 as *const libc::c_char,
                ln: b"authorityRevocationList\0" as *const u8 as *const libc::c_char,
                nid: 882 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5778 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"certificateRevocationList\0" as *const u8 as *const libc::c_char,
                ln: b"certificateRevocationList\0" as *const u8 as *const libc::c_char,
                nid: 883 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5781 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"crossCertificatePair\0" as *const u8 as *const libc::c_char,
                ln: b"crossCertificatePair\0" as *const u8 as *const libc::c_char,
                nid: 884 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5784 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"enhancedSearchGuide\0" as *const u8 as *const libc::c_char,
                ln: b"enhancedSearchGuide\0" as *const u8 as *const libc::c_char,
                nid: 885 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5787 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"protocolInformation\0" as *const u8 as *const libc::c_char,
                ln: b"protocolInformation\0" as *const u8 as *const libc::c_char,
                nid: 886 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5790 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"distinguishedName\0" as *const u8 as *const libc::c_char,
                ln: b"distinguishedName\0" as *const u8 as *const libc::c_char,
                nid: 887 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5793 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"uniqueMember\0" as *const u8 as *const libc::c_char,
                ln: b"uniqueMember\0" as *const u8 as *const libc::c_char,
                nid: 888 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5796 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"houseIdentifier\0" as *const u8 as *const libc::c_char,
                ln: b"houseIdentifier\0" as *const u8 as *const libc::c_char,
                nid: 889 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5799 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"supportedAlgorithms\0" as *const u8 as *const libc::c_char,
                ln: b"supportedAlgorithms\0" as *const u8 as *const libc::c_char,
                nid: 890 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5802 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"deltaRevocationList\0" as *const u8 as *const libc::c_char,
                ln: b"deltaRevocationList\0" as *const u8 as *const libc::c_char,
                nid: 891 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5805 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dmdName\0" as *const u8 as *const libc::c_char,
                ln: b"dmdName\0" as *const u8 as *const libc::c_char,
                nid: 892 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5808 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-alg-PWRI-KEK\0" as *const u8 as *const libc::c_char,
                ln: b"id-alg-PWRI-KEK\0" as *const u8 as *const libc::c_char,
                nid: 893 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5811 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"CMAC\0" as *const u8 as *const libc::c_char,
                ln: b"cmac\0" as *const u8 as *const libc::c_char,
                nid: 894 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes128-GCM\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-gcm\0" as *const u8 as *const libc::c_char,
                nid: 895 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5822 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes128-CCM\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-ccm\0" as *const u8 as *const libc::c_char,
                nid: 896 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5831 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes128-wrap-pad\0" as *const u8 as *const libc::c_char,
                ln: b"id-aes128-wrap-pad\0" as *const u8 as *const libc::c_char,
                nid: 897 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5840 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes192-GCM\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-gcm\0" as *const u8 as *const libc::c_char,
                nid: 898 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5849 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes192-CCM\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-ccm\0" as *const u8 as *const libc::c_char,
                nid: 899 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5858 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes192-wrap-pad\0" as *const u8 as *const libc::c_char,
                ln: b"id-aes192-wrap-pad\0" as *const u8 as *const libc::c_char,
                nid: 900 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5867 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes256-GCM\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-gcm\0" as *const u8 as *const libc::c_char,
                nid: 901 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5876 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes256-CCM\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-ccm\0" as *const u8 as *const libc::c_char,
                nid: 902 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5885 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-aes256-wrap-pad\0" as *const u8 as *const libc::c_char,
                ln: b"id-aes256-wrap-pad\0" as *const u8 as *const libc::c_char,
                nid: 903 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5894 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CTR\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-ctr\0" as *const u8 as *const libc::c_char,
                nid: 904 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-CTR\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-ctr\0" as *const u8 as *const libc::c_char,
                nid: 905 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CTR\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-ctr\0" as *const u8 as *const libc::c_char,
                nid: 906 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-camellia128-wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-camellia128-wrap\0" as *const u8 as *const libc::c_char,
                nid: 907 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5903 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-camellia192-wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-camellia192-wrap\0" as *const u8 as *const libc::c_char,
                nid: 908 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5914 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"id-camellia256-wrap\0" as *const u8 as *const libc::c_char,
                ln: b"id-camellia256-wrap\0" as *const u8 as *const libc::c_char,
                nid: 909 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5925 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"anyExtendedKeyUsage\0" as *const u8 as *const libc::c_char,
                ln: b"Any Extended Key Usage\0" as *const u8 as *const libc::c_char,
                nid: 910 as libc::c_int,
                length: 4 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5936 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MGF1\0" as *const u8 as *const libc::c_char,
                ln: b"mgf1\0" as *const u8 as *const libc::c_char,
                nid: 911 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5940 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSASSA-PSS\0" as *const u8 as *const libc::c_char,
                ln: b"rsassaPss\0" as *const u8 as *const libc::c_char,
                nid: 912 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5949 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-XTS\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-xts\0" as *const u8 as *const libc::c_char,
                nid: 913 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-XTS\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-xts\0" as *const u8 as *const libc::c_char,
                nid: 914 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RC4-HMAC-MD5\0" as *const u8 as *const libc::c_char,
                ln: b"rc4-hmac-md5\0" as *const u8 as *const libc::c_char,
                nid: 915 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CBC-HMAC-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-cbc-hmac-sha1\0" as *const u8 as *const libc::c_char,
                nid: 916 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-192-CBC-HMAC-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"aes-192-cbc-hmac-sha1\0" as *const u8 as *const libc::c_char,
                nid: 917 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CBC-HMAC-SHA1\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-cbc-hmac-sha1\0" as *const u8 as *const libc::c_char,
                nid: 918 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"RSAES-OAEP\0" as *const u8 as *const libc::c_char,
                ln: b"rsaesOaep\0" as *const u8 as *const libc::c_char,
                nid: 919 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5958 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhpublicnumber\0" as *const u8 as *const libc::c_char,
                ln: b"X9.42 DH\0" as *const u8 as *const libc::c_char,
                nid: 920 as libc::c_int,
                length: 7 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5967 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP160r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP160r1\0" as *const u8 as *const libc::c_char,
                nid: 921 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5974 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP160t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP160t1\0" as *const u8 as *const libc::c_char,
                nid: 922 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5983 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP192r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP192r1\0" as *const u8 as *const libc::c_char,
                nid: 923 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(5992 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP192t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP192t1\0" as *const u8 as *const libc::c_char,
                nid: 924 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6001 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP224r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP224r1\0" as *const u8 as *const libc::c_char,
                nid: 925 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6010 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP224t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP224t1\0" as *const u8 as *const libc::c_char,
                nid: 926 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6019 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP256r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP256r1\0" as *const u8 as *const libc::c_char,
                nid: 927 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6028 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP256t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP256t1\0" as *const u8 as *const libc::c_char,
                nid: 928 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6037 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP320r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP320r1\0" as *const u8 as *const libc::c_char,
                nid: 929 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6046 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP320t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP320t1\0" as *const u8 as *const libc::c_char,
                nid: 930 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6055 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP384r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP384r1\0" as *const u8 as *const libc::c_char,
                nid: 931 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6064 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP384t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP384t1\0" as *const u8 as *const libc::c_char,
                nid: 932 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6073 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP512r1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP512r1\0" as *const u8 as *const libc::c_char,
                nid: 933 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6082 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"brainpoolP512t1\0" as *const u8 as *const libc::c_char,
                ln: b"brainpoolP512t1\0" as *const u8 as *const libc::c_char,
                nid: 934 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6091 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PSPECIFIED\0" as *const u8 as *const libc::c_char,
                ln: b"pSpecified\0" as *const u8 as *const libc::c_char,
                nid: 935 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6100 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-stdDH-sha1kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-stdDH-sha1kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 936 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6109 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-stdDH-sha224kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-stdDH-sha224kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 937 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6118 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-stdDH-sha256kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-stdDH-sha256kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 938 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6124 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-stdDH-sha384kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-stdDH-sha384kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 939 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6130 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-stdDH-sha512kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-stdDH-sha512kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 940 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6136 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-cofactorDH-sha1kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-cofactorDH-sha1kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 941 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6142 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-cofactorDH-sha224kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-cofactorDH-sha224kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 942 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6151 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-cofactorDH-sha256kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-cofactorDH-sha256kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 943 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6157 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-cofactorDH-sha384kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-cofactorDH-sha384kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 944 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6163 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dhSinglePass-cofactorDH-sha512kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                ln: b"dhSinglePass-cofactorDH-sha512kdf-scheme\0" as *const u8
                    as *const libc::c_char,
                nid: 945 as libc::c_int,
                length: 6 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6169 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dh-std-kdf\0" as *const u8 as *const libc::c_char,
                ln: b"dh-std-kdf\0" as *const u8 as *const libc::c_char,
                nid: 946 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"dh-cofactor-kdf\0" as *const u8 as *const libc::c_char,
                ln: b"dh-cofactor-kdf\0" as *const u8 as *const libc::c_char,
                nid: 947 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X25519\0" as *const u8 as *const libc::c_char,
                ln: b"X25519\0" as *const u8 as *const libc::c_char,
                nid: 948 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6175 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ED25519\0" as *const u8 as *const libc::c_char,
                ln: b"ED25519\0" as *const u8 as *const libc::c_char,
                nid: 949 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6178 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ChaCha20-Poly1305\0" as *const u8 as *const libc::c_char,
                ln: b"chacha20-poly1305\0" as *const u8 as *const libc::c_char,
                nid: 950 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KxRSA\0" as *const u8 as *const libc::c_char,
                ln: b"kx-rsa\0" as *const u8 as *const libc::c_char,
                nid: 951 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KxECDHE\0" as *const u8 as *const libc::c_char,
                ln: b"kx-ecdhe\0" as *const u8 as *const libc::c_char,
                nid: 952 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KxPSK\0" as *const u8 as *const libc::c_char,
                ln: b"kx-psk\0" as *const u8 as *const libc::c_char,
                nid: 953 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AuthRSA\0" as *const u8 as *const libc::c_char,
                ln: b"auth-rsa\0" as *const u8 as *const libc::c_char,
                nid: 954 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AuthECDSA\0" as *const u8 as *const libc::c_char,
                ln: b"auth-ecdsa\0" as *const u8 as *const libc::c_char,
                nid: 955 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AuthPSK\0" as *const u8 as *const libc::c_char,
                ln: b"auth-psk\0" as *const u8 as *const libc::c_char,
                nid: 956 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KxANY\0" as *const u8 as *const libc::c_char,
                ln: b"kx-any\0" as *const u8 as *const libc::c_char,
                nid: 957 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AuthANY\0" as *const u8 as *const libc::c_char,
                ln: b"auth-any\0" as *const u8 as *const libc::c_char,
                nid: 958 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: 0 as *const libc::c_char,
                ln: 0 as *const libc::c_char,
                nid: 0 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ED448\0" as *const u8 as *const libc::c_char,
                ln: b"ED448\0" as *const u8 as *const libc::c_char,
                nid: 960 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6181 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X448\0" as *const u8 as *const libc::c_char,
                ln: b"X448\0" as *const u8 as *const libc::c_char,
                nid: 961 as libc::c_int,
                length: 3 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6184 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA512-256\0" as *const u8 as *const libc::c_char,
                ln: b"sha512-256\0" as *const u8 as *const libc::c_char,
                nid: 962 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6187 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-128-CBC-HMAC-SHA256\0" as *const u8 as *const libc::c_char,
                ln: b"aes-128-cbc-hmac-sha256\0" as *const u8 as *const libc::c_char,
                nid: 963 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"AES-256-CBC-HMAC-SHA256\0" as *const u8 as *const libc::c_char,
                ln: b"aes-256-cbc-hmac-sha256\0" as *const u8 as *const libc::c_char,
                nid: 964 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA3-224\0" as *const u8 as *const libc::c_char,
                ln: b"sha3-224\0" as *const u8 as *const libc::c_char,
                nid: 965 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6196 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA3-256\0" as *const u8 as *const libc::c_char,
                ln: b"sha3-256\0" as *const u8 as *const libc::c_char,
                nid: 966 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6205 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA3-384\0" as *const u8 as *const libc::c_char,
                ln: b"sha3-384\0" as *const u8 as *const libc::c_char,
                nid: 967 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6214 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA3-512\0" as *const u8 as *const libc::c_char,
                ln: b"sha3-512\0" as *const u8 as *const libc::c_char,
                nid: 968 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6223 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"HKDF\0" as *const u8 as *const libc::c_char,
                ln: b"hkdf\0" as *const u8 as *const libc::c_char,
                nid: 969 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KEM\0" as *const u8 as *const libc::c_char,
                ln: b"kem\0" as *const u8 as *const libc::c_char,
                nid: 970 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6232 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KYBER512\0" as *const u8 as *const libc::c_char,
                ln: b"KYBER512\0" as *const u8 as *const libc::c_char,
                nid: 971 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KYBER512_R3\0" as *const u8 as *const libc::c_char,
                ln: b"KYBER512_R3\0" as *const u8 as *const libc::c_char,
                nid: 972 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KYBER768_R3\0" as *const u8 as *const libc::c_char,
                ln: b"KYBER768_R3\0" as *const u8 as *const libc::c_char,
                nid: 973 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"KYBER1024_R3\0" as *const u8 as *const libc::c_char,
                ln: b"KYBER1024_R3\0" as *const u8 as *const libc::c_char,
                nid: 974 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"DILITHIUM3_R3\0" as *const u8 as *const libc::c_char,
                ln: b"DILITHIUM3_R3\0" as *const u8 as *const libc::c_char,
                nid: 975 as libc::c_int,
                length: 11 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6240 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ffdhe2048\0" as *const u8 as *const libc::c_char,
                ln: b"ffdhe2048\0" as *const u8 as *const libc::c_char,
                nid: 976 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ffdhe4096\0" as *const u8 as *const libc::c_char,
                ln: b"ffdhe4096\0" as *const u8 as *const libc::c_char,
                nid: 977 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHA512-224\0" as *const u8 as *const libc::c_char,
                ln: b"sha512-224\0" as *const u8 as *const libc::c_char,
                nid: 978 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6251 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHAKE128\0" as *const u8 as *const libc::c_char,
                ln: b"shake128\0" as *const u8 as *const libc::c_char,
                nid: 979 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6260 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SHAKE256\0" as *const u8 as *const libc::c_char,
                ln: b"shake256\0" as *const u8 as *const libc::c_char,
                nid: 980 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6269 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SecP256r1Kyber768Draft00\0" as *const u8 as *const libc::c_char,
                ln: b"SecP256r1Kyber768Draft00\0" as *const u8 as *const libc::c_char,
                nid: 981 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6278 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X25519Kyber768Draft00\0" as *const u8 as *const libc::c_char,
                ln: b"X25519Kyber768Draft00\0" as *const u8 as *const libc::c_char,
                nid: 982 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6283 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ffdhe3072\0" as *const u8 as *const libc::c_char,
                ln: b"ffdhe3072\0" as *const u8 as *const libc::c_char,
                nid: 983 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ffdhe8192\0" as *const u8 as *const libc::c_char,
                ln: b"ffdhe8192\0" as *const u8 as *const libc::c_char,
                nid: 984 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLKEM512IPD\0" as *const u8 as *const libc::c_char,
                ln: b"MLKEM512IPD\0" as *const u8 as *const libc::c_char,
                nid: 985 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLKEM768IPD\0" as *const u8 as *const libc::c_char,
                ln: b"MLKEM768IPD\0" as *const u8 as *const libc::c_char,
                nid: 986 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLKEM1024IPD\0" as *const u8 as *const libc::c_char,
                ln: b"MLKEM1024IPD\0" as *const u8 as *const libc::c_char,
                nid: 987 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLKEM512\0" as *const u8 as *const libc::c_char,
                ln: b"MLKEM512\0" as *const u8 as *const libc::c_char,
                nid: 988 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6288 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLKEM768\0" as *const u8 as *const libc::c_char,
                ln: b"MLKEM768\0" as *const u8 as *const libc::c_char,
                nid: 989 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6297 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLKEM1024\0" as *const u8 as *const libc::c_char,
                ln: b"MLKEM1024\0" as *const u8 as *const libc::c_char,
                nid: 990 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6306 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"X25519MLKEM768\0" as *const u8 as *const libc::c_char,
                ln: b"X25519MLKEM768\0" as *const u8 as *const libc::c_char,
                nid: 991 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6315 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SecP256r1MLKEM768\0" as *const u8 as *const libc::c_char,
                ln: b"SecP256r1MLKEM768\0" as *const u8 as *const libc::c_char,
                nid: 992 as libc::c_int,
                length: 5 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6320 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"PQDSA\0" as *const u8 as *const libc::c_char,
                ln: b"PQDSA\0" as *const u8 as *const libc::c_char,
                nid: 993 as libc::c_int,
                length: 8 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6325 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLDSA44\0" as *const u8 as *const libc::c_char,
                ln: b"MLDSA44\0" as *const u8 as *const libc::c_char,
                nid: 994 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6333 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLDSA65\0" as *const u8 as *const libc::c_char,
                ln: b"MLDSA65\0" as *const u8 as *const libc::c_char,
                nid: 995 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6342 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"MLDSA87\0" as *const u8 as *const libc::c_char,
                ln: b"MLDSA87\0" as *const u8 as *const libc::c_char,
                nid: 996 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6351 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"ED25519ph\0" as *const u8 as *const libc::c_char,
                ln: b"ED25519ph\0" as *const u8 as *const libc::c_char,
                nid: 997 as libc::c_int,
                length: 0 as libc::c_int,
                data: 0 as *const libc::c_uchar,
                flags: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = asn1_object_st {
                sn: b"SecP384r1MLKEM1024\0" as *const u8 as *const libc::c_char,
                ln: b"SecP384r1MLKEM1024\0" as *const u8 as *const libc::c_char,
                nid: 998 as libc::c_int,
                length: 9 as libc::c_int,
                data: &*kObjectData.as_ptr().offset(6360 as libc::c_int as isize)
                    as *const uint8_t,
                flags: 0 as libc::c_int,
            };
            init
        },
        asn1_object_st {
            sn: 0 as *const libc::c_char,
            ln: 0 as *const libc::c_char,
            nid: 0,
            length: 0,
            data: 0 as *const libc::c_uchar,
            flags: 0,
        },
    ];
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
