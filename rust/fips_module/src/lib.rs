use std::os::raw::c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn AWS_LC_FIPS_module_version() -> c_int {
    return 22;
}
