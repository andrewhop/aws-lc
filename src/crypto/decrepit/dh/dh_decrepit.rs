#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type dh_st;
    fn BN_GENCB_set(
        callback: *mut BN_GENCB,
        f: Option::<
            unsafe extern "C" fn(libc::c_int, libc::c_int, *mut BN_GENCB) -> libc::c_int,
        >,
        arg: *mut libc::c_void,
    );
    fn DH_new() -> *mut DH;
    fn DH_free(dh: *mut DH);
    fn DH_generate_parameters_ex(
        dh: *mut DH,
        prime_bits: libc::c_int,
        generator: libc::c_int,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_gencb_st {
    pub type_0: uint8_t,
    pub arg: *mut libc::c_void,
    pub callback: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub new_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    pub old_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
}
pub type BN_GENCB = bn_gencb_st;
pub type DH = dh_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct wrapped_callback {
    pub callback: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
    pub arg: *mut libc::c_void,
}
unsafe extern "C" fn callback_wrapper(
    mut event: libc::c_int,
    mut n: libc::c_int,
    mut gencb: *mut BN_GENCB,
) -> libc::c_int {
    let mut wrapped: *mut wrapped_callback = (*gencb).arg as *mut wrapped_callback;
    ((*wrapped).callback).expect("non-null function pointer")(event, n, (*wrapped).arg);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn DH_generate_parameters(
    mut prime_len: libc::c_int,
    mut generator: libc::c_int,
    mut callback: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
    mut cb_arg: *mut libc::c_void,
) -> *mut DH {
    if prime_len < 0 as libc::c_int || generator < 0 as libc::c_int {
        return 0 as *mut DH;
    }
    let mut ret: *mut DH = DH_new();
    if ret.is_null() {
        return 0 as *mut DH;
    }
    let mut gencb_storage: BN_GENCB = bn_gencb_st {
        type_0: 0,
        arg: 0 as *mut libc::c_void,
        callback: C2RustUnnamed { new_style: None },
    };
    let mut cb: *mut BN_GENCB = 0 as *mut BN_GENCB;
    let mut wrapped: wrapped_callback = wrapped_callback {
        callback: None,
        arg: 0 as *mut libc::c_void,
    };
    if callback.is_some() {
        wrapped.callback = callback;
        wrapped.arg = cb_arg;
        cb = &mut gencb_storage;
        BN_GENCB_set(
            cb,
            Some(
                callback_wrapper
                    as unsafe extern "C" fn(
                        libc::c_int,
                        libc::c_int,
                        *mut BN_GENCB,
                    ) -> libc::c_int,
            ),
            &mut wrapped as *mut wrapped_callback as *mut libc::c_void,
        );
    }
    if DH_generate_parameters_ex(ret, prime_len, generator, cb) == 0 {
        DH_free(ret);
        return 0 as *mut DH;
    } else {
        return ret
    };
}
