#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
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
    fn Keccak1600_Absorb(
        A: *mut [uint64_t; 5],
        data: *const uint8_t,
        len: size_t,
        r: size_t,
    ) -> size_t;
    fn Keccak1600_Squeeze(
        A: *mut [uint64_t; 5],
        out: *mut uint8_t,
        len: size_t,
        r: size_t,
        padded: libc::c_int,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct keccak_st {
    pub A: [[uint64_t; 5]; 5],
    pub block_size: size_t,
    pub md_size: size_t,
    pub buf_load: size_t,
    pub buf: [uint8_t; 168],
    pub pad: uint8_t,
    pub state: uint8_t,
}
pub type KECCAK1600_CTX = keccak_st;
pub type KECCAK1600_CTX_x4 = [KECCAK1600_CTX; 4];
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
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[no_mangle]
pub unsafe extern "C" fn SHA3_224(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut ok: libc::c_int = (SHA3_Init(&mut ctx, 224 as libc::c_int as size_t) != 0
        && SHA3_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA3_Final(out, &mut ctx) != 0) as libc::c_int;
    OPENSSL_cleanse(
        &mut ctx as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if ok == 0 as libc::c_int {
        return 0 as *mut uint8_t;
    }
    FIPS_service_indicator_update_state();
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHA3_256(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut ok: libc::c_int = (SHA3_Init(&mut ctx, 256 as libc::c_int as size_t) != 0
        && SHA3_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA3_Final(out, &mut ctx) != 0) as libc::c_int;
    OPENSSL_cleanse(
        &mut ctx as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if ok == 0 as libc::c_int {
        return 0 as *mut uint8_t;
    }
    FIPS_service_indicator_update_state();
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHA3_384(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut ok: libc::c_int = (SHA3_Init(&mut ctx, 384 as libc::c_int as size_t) != 0
        && SHA3_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA3_Final(out, &mut ctx) != 0) as libc::c_int;
    OPENSSL_cleanse(
        &mut ctx as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if ok == 0 as libc::c_int {
        return 0 as *mut uint8_t;
    }
    FIPS_service_indicator_update_state();
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHA3_512(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut ok: libc::c_int = (SHA3_Init(&mut ctx, 512 as libc::c_int as size_t) != 0
        && SHA3_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA3_Final(out, &mut ctx) != 0) as libc::c_int;
    OPENSSL_cleanse(
        &mut ctx as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if ok == 0 as libc::c_int {
        return 0 as *mut uint8_t;
    }
    FIPS_service_indicator_update_state();
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE128(
    mut data: *const uint8_t,
    in_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: size_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut ok: libc::c_int = (SHAKE_Init(
        &mut ctx,
        ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    ) != 0 && SHAKE_Absorb(&mut ctx, data as *const libc::c_void, in_len) != 0
        && SHAKE_Final(out, &mut ctx, out_len) != 0) as libc::c_int;
    OPENSSL_cleanse(
        &mut ctx as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if ok == 0 as libc::c_int {
        return 0 as *mut uint8_t;
    }
    FIPS_service_indicator_update_state();
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE256(
    mut data: *const uint8_t,
    in_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: size_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut ok: libc::c_int = (SHAKE_Init(
        &mut ctx,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    ) != 0 && SHAKE_Absorb(&mut ctx, data as *const libc::c_void, in_len) != 0
        && SHAKE_Final(out, &mut ctx, out_len) != 0) as libc::c_int;
    OPENSSL_cleanse(
        &mut ctx as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if ok == 0 as libc::c_int {
        return 0 as *mut uint8_t;
    }
    FIPS_service_indicator_update_state();
    return out;
}
unsafe extern "C" fn FIPS202_Reset(mut ctx: *mut KECCAK1600_CTX) {
    OPENSSL_memset(
        ((*ctx).A).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[[uint64_t; 5]; 5]>() as libc::c_ulong,
    );
    (*ctx).buf_load = 0 as libc::c_int as size_t;
    (*ctx).state = 0 as libc::c_int as uint8_t;
}
unsafe extern "C" fn FIPS202_Init(
    mut ctx: *mut KECCAK1600_CTX,
    mut pad: uint8_t,
    mut block_size: size_t,
    mut bit_len: size_t,
) -> libc::c_int {
    if pad as libc::c_int != 0x6 as libc::c_int
        && pad as libc::c_int != 0x1f as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if block_size <= ::core::mem::size_of::<[uint8_t; 168]>() as libc::c_ulong {
        FIPS202_Reset(ctx);
        (*ctx).block_size = block_size;
        (*ctx).md_size = bit_len / 8 as libc::c_int as size_t;
        (*ctx).pad = pad;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn FIPS202_Update(
    mut ctx: *mut KECCAK1600_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut data_ptr_copy: *mut uint8_t = data as *mut uint8_t;
    let mut block_size: size_t = (*ctx).block_size;
    let mut num: size_t = 0;
    let mut rem: size_t = 0;
    if (*ctx).state as libc::c_int == 1 as libc::c_int
        || (*ctx).state as libc::c_int == 2 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    num = (*ctx).buf_load;
    if num != 0 as libc::c_int as size_t {
        rem = block_size.wrapping_sub(num);
        if len < rem {
            OPENSSL_memcpy(
                ((*ctx).buf).as_mut_ptr().offset(num as isize) as *mut libc::c_void,
                data_ptr_copy as *const libc::c_void,
                len,
            );
            (*ctx).buf_load = ((*ctx).buf_load).wrapping_add(len);
            return 1 as libc::c_int;
        }
        OPENSSL_memcpy(
            ((*ctx).buf).as_mut_ptr().offset(num as isize) as *mut libc::c_void,
            data_ptr_copy as *const libc::c_void,
            rem,
        );
        data_ptr_copy = data_ptr_copy.offset(rem as isize);
        len = len.wrapping_sub(rem);
        if Keccak1600_Absorb(
            ((*ctx).A).as_mut_ptr(),
            ((*ctx).buf).as_mut_ptr(),
            block_size,
            block_size,
        ) != 0 as libc::c_int as size_t
        {
            return 0 as libc::c_int;
        }
        (*ctx).buf_load = 0 as libc::c_int as size_t;
    }
    if len >= block_size {
        rem = Keccak1600_Absorb(((*ctx).A).as_mut_ptr(), data_ptr_copy, len, block_size);
    } else {
        rem = len;
    }
    if rem != 0 as libc::c_int as size_t {
        OPENSSL_memcpy(
            ((*ctx).buf).as_mut_ptr() as *mut libc::c_void,
            data_ptr_copy.offset(len as isize).offset(-(rem as isize))
                as *const libc::c_void,
            rem,
        );
        (*ctx).buf_load = rem;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn FIPS202_Finalize(
    mut md: *mut uint8_t,
    mut ctx: *mut KECCAK1600_CTX,
) -> libc::c_int {
    let mut block_size: size_t = (*ctx).block_size;
    let mut num: size_t = (*ctx).buf_load;
    if (*ctx).state as libc::c_int == 1 as libc::c_int
        || (*ctx).state as libc::c_int == 2 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        ((*ctx).buf).as_mut_ptr().offset(num as isize) as *mut libc::c_void,
        0 as libc::c_int,
        block_size.wrapping_sub(num),
    );
    (*ctx).buf[num as usize] = (*ctx).pad;
    (*ctx)
        .buf[block_size.wrapping_sub(1 as libc::c_int as size_t)
        as usize] = ((*ctx)
        .buf[block_size.wrapping_sub(1 as libc::c_int as size_t) as usize] as libc::c_int
        | 0x80 as libc::c_int) as uint8_t;
    if Keccak1600_Absorb(
        ((*ctx).A).as_mut_ptr(),
        ((*ctx).buf).as_mut_ptr(),
        block_size,
        block_size,
    ) != 0 as libc::c_int as size_t
    {
        return 0 as libc::c_int;
    }
    (*ctx).buf_load = 0 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA3_Init(
    mut ctx: *mut KECCAK1600_CTX,
    mut bit_len: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if bit_len != 224 as libc::c_int as size_t && bit_len != 256 as libc::c_int as size_t
        && bit_len != 384 as libc::c_int as size_t
        && bit_len != 512 as libc::c_int as size_t
    {
        return 0 as libc::c_int;
    }
    return FIPS202_Init(
        ctx,
        0x6 as libc::c_int as uint8_t,
        (1600 as libc::c_int as size_t)
            .wrapping_sub(bit_len * 2 as libc::c_int as size_t)
            / 8 as libc::c_int as size_t,
        bit_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn SHA3_Update(
    mut ctx: *mut KECCAK1600_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if data.is_null() && len != 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    return FIPS202_Update(ctx, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn SHA3_Final(
    mut md: *mut uint8_t,
    mut ctx: *mut KECCAK1600_CTX,
) -> libc::c_int {
    if md.is_null() || ctx.is_null() {
        return 0 as libc::c_int;
    }
    if (*ctx).md_size == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    if FIPS202_Finalize(md, ctx) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    Keccak1600_Squeeze(
        ((*ctx).A).as_mut_ptr(),
        md,
        (*ctx).md_size,
        (*ctx).block_size,
        (*ctx).state as libc::c_int,
    );
    (*ctx).state = 2 as libc::c_int as uint8_t;
    FIPS_service_indicator_update_state();
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE_Init(
    mut ctx: *mut KECCAK1600_CTX,
    mut block_size: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if block_size
        != ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t
        && block_size
            != ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t
    {
        return 0 as libc::c_int;
    }
    return FIPS202_Init(
        ctx,
        0x1f as libc::c_int as uint8_t,
        block_size,
        0 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE_Absorb(
    mut ctx: *mut KECCAK1600_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if data.is_null() && len != 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    return FIPS202_Update(ctx, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE_Final(
    mut md: *mut uint8_t,
    mut ctx: *mut KECCAK1600_CTX,
    mut len: size_t,
) -> libc::c_int {
    if ctx.is_null() || md.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).md_size = len;
    if (*ctx).md_size == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    if FIPS202_Finalize(md, ctx) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    Keccak1600_Squeeze(
        ((*ctx).A).as_mut_ptr(),
        md,
        (*ctx).md_size,
        (*ctx).block_size,
        (*ctx).state as libc::c_int,
    );
    (*ctx).state = 2 as libc::c_int as uint8_t;
    FIPS_service_indicator_update_state();
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE_Squeeze(
    mut md: *mut uint8_t,
    mut ctx: *mut KECCAK1600_CTX,
    mut len: size_t,
) -> libc::c_int {
    let mut block_bytes: size_t = 0;
    if ctx.is_null() || md.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).md_size = len;
    if (*ctx).md_size == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    if (*ctx).state as libc::c_int == 2 as libc::c_int {
        return 0 as libc::c_int;
    }
    if (*ctx).state as libc::c_int == 0 as libc::c_int {
        if FIPS202_Finalize(md, ctx) == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if (*ctx).buf_load != 0 as libc::c_int as size_t {
        if len <= (*ctx).buf_load {
            OPENSSL_memcpy(
                md as *mut libc::c_void,
                ((*ctx).buf)
                    .as_mut_ptr()
                    .offset((*ctx).block_size as isize)
                    .offset(-((*ctx).buf_load as isize)) as *const libc::c_void,
                len,
            );
            (*ctx).buf_load = ((*ctx).buf_load).wrapping_sub(len);
            return 1 as libc::c_int;
        } else {
            OPENSSL_memcpy(
                md as *mut libc::c_void,
                ((*ctx).buf)
                    .as_mut_ptr()
                    .offset((*ctx).block_size as isize)
                    .offset(-((*ctx).buf_load as isize)) as *const libc::c_void,
                (*ctx).buf_load,
            );
            md = md.offset((*ctx).buf_load as isize);
            len = len.wrapping_sub((*ctx).buf_load);
            (*ctx).buf_load = 0 as libc::c_int as size_t;
        }
    }
    if len > (*ctx).block_size {
        block_bytes = (*ctx).block_size * (len / (*ctx).block_size);
        Keccak1600_Squeeze(
            ((*ctx).A).as_mut_ptr(),
            md,
            block_bytes,
            (*ctx).block_size,
            (*ctx).state as libc::c_int,
        );
        md = md.offset(block_bytes as isize);
        len = len.wrapping_sub(block_bytes);
        (*ctx).state = 1 as libc::c_int as uint8_t;
    }
    if len > 0 as libc::c_int as size_t {
        Keccak1600_Squeeze(
            ((*ctx).A).as_mut_ptr(),
            ((*ctx).buf).as_mut_ptr(),
            (*ctx).block_size,
            (*ctx).block_size,
            (*ctx).state as libc::c_int,
        );
        OPENSSL_memcpy(
            md as *mut libc::c_void,
            ((*ctx).buf).as_mut_ptr() as *const libc::c_void,
            len,
        );
        (*ctx).buf_load = ((*ctx).block_size).wrapping_sub(len);
        (*ctx).state = 1 as libc::c_int as uint8_t;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE128_Init_x4(
    mut ctx: *mut KECCAK1600_CTX_x4,
) -> libc::c_int {
    let mut ok: libc::c_int = (SHAKE_Init(
        &mut *(*ctx).as_mut_ptr().offset(0 as libc::c_int as isize),
        ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    ) != 0
        && SHAKE_Init(
            &mut *(*ctx).as_mut_ptr().offset(1 as libc::c_int as isize),
            ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        ) != 0
        && SHAKE_Init(
            &mut *(*ctx).as_mut_ptr().offset(2 as libc::c_int as isize),
            ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        ) != 0
        && SHAKE_Init(
            &mut *(*ctx).as_mut_ptr().offset(3 as libc::c_int as isize),
            ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        ) != 0) as libc::c_int;
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE128_Absorb_once_x4(
    mut ctx: *mut KECCAK1600_CTX_x4,
    mut data0: *const libc::c_void,
    mut data1: *const libc::c_void,
    mut data2: *const libc::c_void,
    mut data3: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut ok: libc::c_int = (SHAKE_Absorb(
        &mut *(*ctx).as_mut_ptr().offset(0 as libc::c_int as isize),
        data0,
        len,
    ) != 0
        && SHAKE_Absorb(
            &mut *(*ctx).as_mut_ptr().offset(1 as libc::c_int as isize),
            data1,
            len,
        ) != 0
        && SHAKE_Absorb(
            &mut *(*ctx).as_mut_ptr().offset(2 as libc::c_int as isize),
            data2,
            len,
        ) != 0
        && SHAKE_Absorb(
            &mut *(*ctx).as_mut_ptr().offset(3 as libc::c_int as isize),
            data3,
            len,
        ) != 0) as libc::c_int;
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE128_Squeezeblocks_x4(
    mut md0: *mut uint8_t,
    mut md1: *mut uint8_t,
    mut md2: *mut uint8_t,
    mut md3: *mut uint8_t,
    mut ctx: *mut KECCAK1600_CTX_x4,
    mut blks: size_t,
) -> libc::c_int {
    let mut ok: libc::c_int = (SHAKE_Squeeze(
        md0,
        &mut *(*ctx).as_mut_ptr().offset(0 as libc::c_int as isize),
        blks
            * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
    ) != 0
        && SHAKE_Squeeze(
            md1,
            &mut *(*ctx).as_mut_ptr().offset(1 as libc::c_int as isize),
            blks
                * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int) as size_t,
        ) != 0
        && SHAKE_Squeeze(
            md2,
            &mut *(*ctx).as_mut_ptr().offset(2 as libc::c_int as isize),
            blks
                * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int) as size_t,
        ) != 0
        && SHAKE_Squeeze(
            md3,
            &mut *(*ctx).as_mut_ptr().offset(3 as libc::c_int as isize),
            blks
                * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int) as size_t,
        ) != 0) as libc::c_int;
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn SHAKE256_x4(
    mut data0: *const uint8_t,
    mut data1: *const uint8_t,
    mut data2: *const uint8_t,
    mut data3: *const uint8_t,
    in_len: size_t,
    mut out0: *mut uint8_t,
    mut out1: *mut uint8_t,
    mut out2: *mut uint8_t,
    mut out3: *mut uint8_t,
    mut out_len: size_t,
) -> libc::c_int {
    let mut ok: libc::c_int = (!(SHAKE256(data0, in_len, out0, out_len)).is_null()
        && !(SHAKE256(data1, in_len, out1, out_len)).is_null()
        && !(SHAKE256(data2, in_len, out2, out_len)).is_null()
        && !(SHAKE256(data3, in_len, out3, out_len)).is_null()) as libc::c_int;
    return ok;
}
