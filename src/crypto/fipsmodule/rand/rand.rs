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
    fn free(_: *mut libc::c_void);
    fn abort() -> !;
    fn CRYPTO_sysrand(buf: *mut uint8_t, len: size_t);
    fn CRYPTO_sysrand_for_seed(buf: *mut uint8_t, len: size_t);
    fn CRYPTO_sysrand_if_available(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn rand_fork_unsafe_buffering_enabled() -> libc::c_int;
    fn CTR_DRBG_init(
        drbg: *mut CTR_DRBG_STATE,
        entropy: *const uint8_t,
        personalization: *const uint8_t,
        personalization_len: size_t,
    ) -> libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn CTR_DRBG_reseed(
        drbg: *mut CTR_DRBG_STATE,
        entropy: *const uint8_t,
        additional_data: *const uint8_t,
        additional_data_len: size_t,
    ) -> libc::c_int;
    fn CTR_DRBG_generate(
        drbg: *mut CTR_DRBG_STATE,
        out: *mut uint8_t,
        out_len: size_t,
        additional_data: *const uint8_t,
        additional_data_len: size_t,
    ) -> libc::c_int;
    fn CTR_DRBG_clear(drbg: *mut CTR_DRBG_STATE);
    fn CRYPTO_get_snapsafe_generation(
        snapsafe_generation_number: *mut uint32_t,
    ) -> libc::c_int;
    fn CRYPTO_get_thread_local(value: thread_local_data_t) -> *mut libc::c_void;
    fn CRYPTO_set_thread_local(
        index: thread_local_data_t,
        value: *mut libc::c_void,
        destructor: thread_local_destructor_t,
    ) -> libc::c_int;
    fn CRYPTO_get_fork_generation() -> uint64_t;
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
pub struct ctr_drbg_state_st {
    pub ks: AES_KEY,
    pub block: block128_f,
    pub ctr: ctr128_f,
    pub counter: [uint8_t; 16],
    pub reseed_counter: uint64_t,
}
pub type ctr128_f = Option::<
    unsafe extern "C" fn(
        *const uint8_t,
        *mut uint8_t,
        size_t,
        *const AES_KEY,
        *const uint8_t,
    ) -> (),
>;
pub type AES_KEY = aes_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
pub type CTR_DRBG_STATE = ctr_drbg_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rand_thread_state {
    pub drbg: CTR_DRBG_STATE,
    pub fork_generation: uint64_t,
    pub calls: libc::c_uint,
    pub fork_unsafe_buffering: libc::c_int,
    pub snapsafe_generation: uint32_t,
}
pub type thread_local_data_t = libc::c_uint;
pub const NUM_OPENSSL_THREAD_LOCALS: thread_local_data_t = 5;
pub const OPENSSL_THREAD_LOCAL_TEST: thread_local_data_t = 4;
pub const AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE: thread_local_data_t = 3;
pub const OPENSSL_THREAD_LOCAL_FIPS_COUNTERS: thread_local_data_t = 2;
pub const OPENSSL_THREAD_LOCAL_RAND: thread_local_data_t = 1;
pub const OPENSSL_THREAD_LOCAL_ERR: thread_local_data_t = 0;
pub type thread_local_destructor_t = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> (),
>;
#[inline]
unsafe extern "C" fn have_rdrand() -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn have_fast_rdrand() -> libc::c_int {
    return 0 as libc::c_int;
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
static mut kReseedInterval: libc::c_uint = 4096 as libc::c_int as libc::c_uint;
unsafe extern "C" fn rand_thread_state_free(mut state_in: *mut libc::c_void) {
    let mut state: *mut rand_thread_state = state_in as *mut rand_thread_state;
    if state_in.is_null() {
        return;
    }
    OPENSSL_cleanse(
        state as *mut libc::c_void,
        ::core::mem::size_of::<rand_thread_state>() as libc::c_ulong,
    );
    free(state as *mut libc::c_void);
}
unsafe extern "C" fn rdrand(mut buf: *mut uint8_t, mut len: size_t) -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn rand_get_seed(
    mut state: *mut rand_thread_state,
    mut seed: *mut uint8_t,
    mut out_want_additional_input: *mut libc::c_int,
) {
    CRYPTO_sysrand_for_seed(seed, 48 as libc::c_int as size_t);
    *out_want_additional_input = 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RAND_bytes_with_additional_data(
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut user_additional_data: *const uint8_t,
) {
    if out_len == 0 as libc::c_int as size_t {
        return;
    }
    let fork_generation: uint64_t = CRYPTO_get_fork_generation();
    let fork_unsafe_buffering: libc::c_int = rand_fork_unsafe_buffering_enabled();
    let mut snapsafe_generation: uint32_t = 0 as libc::c_int as uint32_t;
    let mut snapsafe_status: libc::c_int = CRYPTO_get_snapsafe_generation(
        &mut snapsafe_generation,
    );
    let mut additional_data: [uint8_t; 32] = [0; 32];
    if have_fast_rdrand() == 0
        || rdrand(
            additional_data.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        ) == 0
    {
        if snapsafe_status != 0 as libc::c_int
            && fork_generation != 0 as libc::c_int as uint64_t
            || fork_unsafe_buffering != 0
        {
            OPENSSL_memset(
                additional_data.as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
            );
        } else if have_rdrand() == 0 {
            CRYPTO_sysrand(
                additional_data.as_mut_ptr(),
                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
            );
        } else if CRYPTO_sysrand_if_available(
            additional_data.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        ) == 0
            && rdrand(
                additional_data.as_mut_ptr(),
                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
            ) == 0
        {
            CRYPTO_sysrand(
                additional_data.as_mut_ptr(),
                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
            );
        }
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong {
        additional_data[i
            as usize] = (additional_data[i as usize] as libc::c_int
            ^ *user_additional_data.offset(i as isize) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let mut stack_state: rand_thread_state = rand_thread_state {
        drbg: ctr_drbg_state_st {
            ks: aes_key_st {
                rd_key: [0; 60],
                rounds: 0,
            },
            block: None,
            ctr: None,
            counter: [0; 16],
            reseed_counter: 0,
        },
        fork_generation: 0,
        calls: 0,
        fork_unsafe_buffering: 0,
        snapsafe_generation: 0,
    };
    let mut state: *mut rand_thread_state = CRYPTO_get_thread_local(
        OPENSSL_THREAD_LOCAL_RAND,
    ) as *mut rand_thread_state;
    if state.is_null() {
        state = malloc(::core::mem::size_of::<rand_thread_state>() as libc::c_ulong)
            as *mut rand_thread_state;
        if !state.is_null() {
            OPENSSL_memset(
                state as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<rand_thread_state>() as libc::c_ulong,
            );
        }
        if state.is_null()
            || CRYPTO_set_thread_local(
                OPENSSL_THREAD_LOCAL_RAND,
                state as *mut libc::c_void,
                Some(
                    rand_thread_state_free
                        as unsafe extern "C" fn(*mut libc::c_void) -> (),
                ),
            ) == 0
        {
            state = &mut stack_state;
        }
        let mut seed: [uint8_t; 48] = [0; 48];
        let mut want_additional_input: libc::c_int = 0;
        rand_get_seed(state, seed.as_mut_ptr(), &mut want_additional_input);
        let mut personalization: [uint8_t; 48] = [
            0 as libc::c_int as uint8_t,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut personalization_len: size_t = 0 as libc::c_int as size_t;
        if CTR_DRBG_init(
            &mut (*state).drbg,
            seed.as_mut_ptr() as *const uint8_t,
            personalization.as_mut_ptr(),
            personalization_len,
        ) == 0
        {
            abort();
        }
        (*state).calls = 0 as libc::c_int as libc::c_uint;
        (*state).fork_generation = fork_generation;
        (*state).fork_unsafe_buffering = fork_unsafe_buffering;
        (*state).snapsafe_generation = snapsafe_generation;
        OPENSSL_cleanse(
            seed.as_mut_ptr() as *mut libc::c_void,
            48 as libc::c_int as size_t,
        );
        OPENSSL_cleanse(
            personalization.as_mut_ptr() as *mut libc::c_void,
            48 as libc::c_int as size_t,
        );
    }
    if (*state).calls >= kReseedInterval
        || (*state).snapsafe_generation != snapsafe_generation
        || (*state).fork_generation != fork_generation
        || (*state).fork_unsafe_buffering != fork_unsafe_buffering
    {
        let mut seed_0: [uint8_t; 48] = [0; 48];
        let mut want_additional_input_0: libc::c_int = 0;
        rand_get_seed(state, seed_0.as_mut_ptr(), &mut want_additional_input_0);
        let mut add_data_for_reseed: [uint8_t; 48] = [0; 48];
        let mut add_data_for_reseed_len: size_t = 0 as libc::c_int as size_t;
        if CTR_DRBG_reseed(
            &mut (*state).drbg,
            seed_0.as_mut_ptr() as *const uint8_t,
            add_data_for_reseed.as_mut_ptr(),
            add_data_for_reseed_len,
        ) == 0
        {
            abort();
        }
        (*state).calls = 0 as libc::c_int as libc::c_uint;
        (*state).fork_generation = fork_generation;
        (*state).fork_unsafe_buffering = fork_unsafe_buffering;
        (*state).snapsafe_generation = snapsafe_generation;
        OPENSSL_cleanse(
            seed_0.as_mut_ptr() as *mut libc::c_void,
            48 as libc::c_int as size_t,
        );
        OPENSSL_cleanse(
            add_data_for_reseed.as_mut_ptr() as *mut libc::c_void,
            48 as libc::c_int as size_t,
        );
    }
    let mut first_call: libc::c_int = 1 as libc::c_int;
    while out_len > 0 as libc::c_int as size_t {
        let mut todo: size_t = out_len;
        if todo > 65536 as libc::c_int as size_t {
            todo = 65536 as libc::c_int as size_t;
        }
        if CTR_DRBG_generate(
            &mut (*state).drbg,
            out,
            todo,
            additional_data.as_mut_ptr(),
            if first_call != 0 {
                ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
            } else {
                0 as libc::c_int as libc::c_ulong
            },
        ) == 0
        {
            abort();
        }
        out = out.offset(todo as isize);
        out_len = out_len.wrapping_sub(todo);
        (*state).calls = ((*state).calls).wrapping_add(1);
        (*state).calls;
        first_call = 0 as libc::c_int;
    }
    if state == &mut stack_state as *mut rand_thread_state {
        CTR_DRBG_clear(&mut (*state).drbg);
    }
    OPENSSL_cleanse(
        additional_data.as_mut_ptr() as *mut libc::c_void,
        32 as libc::c_int as size_t,
    );
    if 1 as libc::c_int == CRYPTO_get_snapsafe_generation(&mut snapsafe_generation) {
        if snapsafe_generation != (*state).snapsafe_generation {
            abort();
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RAND_bytes(
    mut out: *mut uint8_t,
    mut out_len: size_t,
) -> libc::c_int {
    static mut kZeroAdditionalData: [uint8_t; 32] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    RAND_bytes_with_additional_data(out, out_len, kZeroAdditionalData.as_ptr());
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RAND_priv_bytes(
    mut out: *mut uint8_t,
    mut out_len: size_t,
) -> libc::c_int {
    return RAND_bytes(out, out_len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RAND_pseudo_bytes(
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return RAND_bytes(buf, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RAND_get_system_entropy_for_custom_prng(
    mut buf: *mut uint8_t,
    mut len: size_t,
) {
    if len > 256 as libc::c_int as size_t {
        abort();
    }
    CRYPTO_sysrand_for_seed(buf, len);
}
