#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

use std::alloc::{Layout, dealloc};
use std::ffi::{c_char, c_int};
use std::os::raw::c_void;
use std::ptr;
pub type size_t = libc::size_t;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return libc::memcpy(dst, src, n);
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
    return libc::memset(dst, c, n as usize);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_mem_ctrl(mut mode: libc::c_int) -> libc::c_int {
    return 0 as libc::c_int;
}
static mut realloc_impl: Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        size_t,
        *const libc::c_char,
        libc::c_int,
    ) -> *mut libc::c_void,
> = None;
static mut free_impl: Option<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, libc::c_int) -> (),
> = None;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_set_mem_functions(
    mut m: Option<
        unsafe extern "C" fn(size_t, *const libc::c_char, libc::c_int) -> *mut libc::c_void,
    >,
    mut r: Option<
        unsafe extern "C" fn(
            *mut libc::c_void,
            size_t,
            *const libc::c_char,
            libc::c_int,
        ) -> *mut libc::c_void,
    >,
    mut f: Option<unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, libc::c_int) -> ()>,
) -> libc::c_int {
    return 1 as libc::c_int;
}

const OPENSSL_MALLOC_PREFIX: usize = 8;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_malloc(size: usize) -> *mut libc::c_void {
    // Check for overflow
    if size.checked_add(OPENSSL_MALLOC_PREFIX).is_none() {
        return std::ptr::null_mut();
    }

    // Allocate memory
    let total_size = size + OPENSSL_MALLOC_PREFIX;
    let layout = std::alloc::Layout::from_size_align(total_size, std::mem::align_of::<usize>())
        .unwrap_or_else(|_| {
            std::process::abort(); // Should never happen with valid sizes
        });

    let ptr = std::alloc::alloc(layout);
    if ptr.is_null() {
        // Handle allocation failure - equivalent to "goto err" in C
        return std::ptr::null_mut();
    }

    // Store the size at the beginning of the allocated block
    *(ptr as *mut usize) = size;

    // Return pointer after the prefix
    let result_ptr = ptr.add(OPENSSL_MALLOC_PREFIX);
    result_ptr as *mut libc::c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_zalloc(mut size: size_t) -> *mut libc::c_void {
    let mut ret: *mut libc::c_void = OPENSSL_malloc(size as usize);
    if !ret.is_null() {
        OPENSSL_memset(ret, 0 as libc::c_int, size);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_calloc(mut num: size_t, mut size: size_t) -> *mut libc::c_void {
    if size != 0 as libc::c_int as size_t && num > size_t::MAX.wrapping_div(size) {
        return 0 as *mut libc::c_void;
    }
    return OPENSSL_zalloc(num * size);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_free(orig_ptr: *mut c_void) {
    // Early return if pointer is null
    if orig_ptr.is_null() {
        return;
    }

    // Calculate the actual allocation start address
    let ptr = (orig_ptr as *mut u8).offset(-(OPENSSL_MALLOC_PREFIX as isize));

    // Read the original allocation size
    let size = *(ptr as *const usize);

    // Zero out the memory before freeing (security precaution)
    OPENSSL_cleanse(
        ptr as *mut c_void,
        (size + OPENSSL_MALLOC_PREFIX) as libc::size_t,
    );

    // Create the same layout that was used for allocation
    let layout =
        Layout::from_size_align(size + OPENSSL_MALLOC_PREFIX, std::mem::align_of::<usize>())
            .unwrap_or_else(|_| std::process::abort()); // Should never happen with valid memory

    // Free the memory
    dealloc(ptr, layout);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_realloc(orig_ptr: *mut c_void, new_size: usize) -> *mut c_void {
    // If input pointer is NULL, just allocate new memory
    if orig_ptr.is_null() {
        return OPENSSL_malloc(new_size);
    }

    // Get the original size by accessing the metadata stored before orig_ptr
    let ptr = (orig_ptr as *mut u8).offset(-(OPENSSL_MALLOC_PREFIX as isize));
    let old_size = *(ptr as *const usize);

    // Allocate new memory with the requested size
    let ret = OPENSSL_malloc(new_size);
    if ret.is_null() {
        return ptr::null_mut();
    }

    // Determine how many bytes to copy (smaller of old and new sizes)
    let to_copy = std::cmp::min(old_size, new_size);

    // Copy memory contents from old location to new
    ptr::copy_nonoverlapping(orig_ptr as *const u8, ret as *mut u8, to_copy);

    // Free the original memory
    OPENSSL_free(orig_ptr);

    ret
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_cleanse(mut ptr: *mut libc::c_void, mut len: size_t) {
    if ptr.is_null() || len == 0 as libc::c_int as size_t {
        return;
    }
    OPENSSL_memset(ptr, 0 as libc::c_int, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_clear_free(mut ptr: *mut libc::c_void, mut unused: size_t) {
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
    return OPENSSL_malloc(size as usize);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_secure_zalloc(mut size: size_t) -> *mut libc::c_void {
    return OPENSSL_zalloc(size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_secure_clear_free(mut ptr: *mut libc::c_void, mut len: size_t) {
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
            | *a.offset(i as isize) as libc::c_int ^ *b.offset(i as isize) as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
    }
    return x as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_hash32(mut ptr: *const libc::c_void, mut len: size_t) -> uint32_t {
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
    return OPENSSL_hash32(s as *const libc::c_void, libc::strlen(s));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strnlen(mut s: *const libc::c_char, mut len: size_t) -> size_t {
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
pub unsafe extern "C" fn OPENSSL_strdup(mut s: *const libc::c_char) -> *mut libc::c_char {
    if s.is_null() {
        return 0 as *mut libc::c_char;
    }
    return OPENSSL_memdup(s as *const libc::c_void, (libc::strlen(s)).wrapping_add(1))
        as *mut libc::c_char;
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
    return (OPENSSL_isdigit(c) != 0
        || c >= 'a' as i32 && c <= 'f' as i32
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
                *str.offset(
                    (2 as libc::c_int as size_t * i).wrapping_add(1 as libc::c_int as size_t)
                        as isize,
                ) as libc::c_int,
            ) == 0
        {
            OPENSSL_free(buf as *mut libc::c_void);
            return 0 as *mut uint8_t;
        }
        *buf.offset(i as isize) =
            ((hi as libc::c_int) << 4 as libc::c_int | lo as libc::c_int) as uint8_t;
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
    return (c == '\t' as i32
        || c == '\n' as i32
        || c == '\u{b}' as i32
        || c == '\u{c}' as i32
        || c == '\r' as i32
        || c == ' ' as i32) as libc::c_int;
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
            return -(1 as libc::c_int);
        } else if aa > bb {
            return 1 as libc::c_int;
        } else if aa == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
    }
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
            return -(1 as libc::c_int);
        } else if aa > bb {
            return 1 as libc::c_int;
        } else if aa == 0 as libc::c_int {
            return 0 as libc::c_int;
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

unsafe extern "C" {
    fn vsnprintf(
        s: *mut libc::c_char,
        n: libc::size_t,
        format: *const libc::c_char,
        args: ::core::ffi::VaList,
    ) -> libc::c_int;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_vsnprintf(
    mut buf: *mut libc::c_char,
    mut n: size_t,
    mut format: *const libc::c_char,
    mut args: ::core::ffi::VaList,
) -> libc::c_int {
    vsnprintf(buf, n, format, args)
}

// Function pointer types for cleaner code
type AllocateFn = unsafe extern "C" fn(usize) -> *mut c_void;
type DeallocateFn = unsafe extern "C" fn(*mut c_void);
type ReallocateFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_vasprintf_internal(
    str: *mut *mut c_char,
    format: *const c_char,
    args: ::core::ffi::VaList,
    system_malloc: c_int,
) -> c_int {
    // Input validation
    if str.is_null() || format.is_null() {
        set_errno_enomem();
        return -1;
    }

    // Select memory management functions based on system_malloc flag
    let (allocate, deallocate, reallocate): (AllocateFn, DeallocateFn, ReallocateFn) =
        if system_malloc != 0 {
            (libc::malloc, libc::free, libc::realloc)
        } else {
            (OPENSSL_malloc, OPENSSL_free, OPENSSL_realloc)
        };

    // Initial buffer size - TODO: optimize initial size based on format string analysis
    const INITIAL_SIZE: usize = 64;
    let mut candidate_len = INITIAL_SIZE;

    // Allocate initial buffer
    let mut candidate = allocate(candidate_len);
    if candidate.is_null() {
        *str = ptr::null_mut();
        set_errno_enomem();
        return -1;
    }
    let ret = args.with_copy(|copy| {
        // Inside this closure, 'copy' is the copied VaList that you can use
        vsnprintf(candidate as *mut c_char, candidate_len, format, copy)
    });
    if ret < 0 {
        deallocate(candidate);
        *str = ptr::null_mut();
        set_errno_enomem();
        return -1;
    }

    // Check if we need a larger buffer
    if (ret as usize) >= candidate_len {
        // Buffer too small, reallocate with exact size needed
        candidate_len = (ret as usize) + 1;
        let tmp = reallocate(candidate, candidate_len);

        if tmp.is_null() {
            deallocate(candidate);
            *str = ptr::null_mut();
            set_errno_enomem();
            return -1;
        }

        candidate = tmp;

        // Second formatting attempt with correctly sized buffer
        let final_ret = vsnprintf(candidate as *mut c_char, candidate_len, format, args);

        // Sanity check - this should not happen with a properly functioning vsnprintf
        if final_ret < 0 || (final_ret as usize) >= candidate_len {
            deallocate(candidate);
            *str = ptr::null_mut();
            set_errno_enomem();
            return -1;
        }
    }

    // Success: assign the result and return length
    *str = candidate as *mut c_char;
    ret
}

/// Set errno to ENOMEM in a cross-platform way
fn set_errno_enomem() {
    // Use std::io::Error to set errno in a cross-platform way
    let error = std::io::Error::from_raw_os_error(
        #[cfg(unix)]
        libc::ENOMEM,
        #[cfg(windows)]
        12, // ERROR_NOT_ENOUGH_MEMORY
    );

    // This will set the thread-local errno
    std::io::Error::last_os_error();
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
    return l.wrapping_add(libc::strlen(src));
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
