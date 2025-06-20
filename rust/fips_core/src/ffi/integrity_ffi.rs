use core::ffi::c_int;

use crate::{hash::sha2, integrity::get_fips_digest};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn AWS_LC_FIPS_get_digest(out: *mut u8, out_len: usize) -> c_int {
    // Safety checks for null pointers
    if out.is_null() || out_len < sha2::SHA256_DIGEST_LEN {
        return 0;
    }

    let output = unsafe { core::slice::from_raw_parts_mut(out, sha2::SHA256_DIGEST_LEN) };

    // Call fips_core's digest function with input and output buffer
    let digest = get_fips_digest();
    output.copy_from_slice(&digest);
    return 1;
}
