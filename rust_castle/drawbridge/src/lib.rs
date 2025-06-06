#[unsafe(no_mangle)]
pub extern "C" fn aws_lc_add_double(left: u64, right: u64) -> u64 {
    bailey::add_double(left, right)
}

#[unsafe(no_mangle)]
pub extern "C" fn aws_lc_add(left: u64, right: u64) -> u64 {
    keep::add(left, right)
}

/// SHA256 writes the digest of |len| bytes from |data| to |out| and returns
/// |out|. There must be at least |SHA256_DIGEST_LENGTH| bytes of space in
/// |out|.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `data` must be a valid pointer to an array of at least `len` bytes
/// - `out` must be a valid pointer to an array of at least `SHA256_DIGEST_LENGTH` bytes
/// - The memory referenced by `data` must not be modified during the call
/// - The memory referenced by `out` must be properly aligned and not overlap with `data`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256(data: *const u8, len: usize, out: *mut u8) -> *mut u8 {
    // Safety checks for null pointers
    if data.is_null() || out.is_null() {
        return out;
    }

    // Convert C pointers to Rust slices
    let input = unsafe { core::slice::from_raw_parts(data, len) };

    // Call Keep's digest function
    let digest = keep::hash::sha256::digest(input);

    // Copy the result to the output buffer
    unsafe {
        core::ptr::copy_nonoverlapping(digest.as_ptr(), out, keep::hash::sha256::DIGEST_LEN);
    }

    // Return the output pointer as required by the C API
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = aws_lc_add(2, 3);
        assert_eq!(result, 5);

        let result = aws_lc_add_double(2, 3);
        assert_eq!(result, 10);
    }

    #[test]
    fn test_sha256() {
        // Test vector: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let input = b"abc";
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let mut output = [0u8; keep::hash::sha256::DIGEST_LEN];

        unsafe {
            SHA256(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        assert_eq!(output, expected);
    }
}
