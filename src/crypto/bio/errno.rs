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
    fn __errno_location() -> *mut libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bio_errno_should_retry(
    mut return_value: libc::c_int,
) -> libc::c_int {
    if return_value != -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    return (*__errno_location() == 11 as libc::c_int
        || *__errno_location() == 107 as libc::c_int
        || *__errno_location() == 4 as libc::c_int
        || *__errno_location() == 11 as libc::c_int
        || *__errno_location() == 71 as libc::c_int
        || *__errno_location() == 115 as libc::c_int
        || *__errno_location() == 114 as libc::c_int || 0 as libc::c_int != 0)
        as libc::c_int;
}
