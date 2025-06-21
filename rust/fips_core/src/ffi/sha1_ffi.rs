use crate::digest::{Digest, sha1};

/// SHA_CTX is a type alias for the sha1::State struct
#[allow(non_camel_case_types)]
pub type SHA_CTX = sha1::State;

/// SHA1_Init initialises |sha| and returns 1.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA_CTX` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA1_Init(sha: *mut SHA_CTX) -> i32 {
    if sha.is_null() {
        return 0;
    }
    let sha = unsafe { &mut *sha };

    // Initialize the context
    sha.init();

    // Return 1 on success as per the C API
    1
}

/// SHA1_Update adds |len| bytes from |data| to |sha| and returns 1.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA_CTX` struct
/// - `data` must be a valid pointer to an array of at least `len` bytes
/// - The memory referenced by `data` must not be modified during the call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA1_Update(
    sha: *mut SHA_CTX,
    data: *const core::ffi::c_void,
    len: usize,
) -> i32 {
    if len == 0 {
        return 1;
    }
    if sha.is_null() || data.is_null() {
        return 0;
    }

    // Convert the void pointer to a u8 slice
    let input = unsafe { core::slice::from_raw_parts(data as *const u8, len) };
    let sha = unsafe { &mut *sha };
    sha.update(input);
    1
}

/// SHA1_Final adds the final padding to |sha| and writes the resulting digest
/// to |out|, which must have at least |SHA_DIGEST_LENGTH| bytes of space. It
/// returns one on success and zero on programmer error.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA_CTX` struct
/// - `out` must be a valid pointer to an array of at least `SHA_DIGEST_LENGTH` bytes
/// - The memory referenced by `out` must be properly aligned
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA1_Final(out: *mut u8, sha: *mut SHA_CTX) -> i32 {
    if sha.is_null() || out.is_null() {
        return 0;
    }

    // Create a mutable slice for the output buffer
    let output = unsafe { core::slice::from_raw_parts_mut(out, sha1::SHA1_DIGEST_LEN) };

    // Finalize the hash and write to the output buffer
    let context = unsafe { &mut *sha };
    context.finalize(output);

    // Return 1 on success as per the C API
    1
}

/// SHA1 writes the digest of |len| bytes from |data| to |out| and returns
/// |out|. There must be at least |SHA_DIGEST_LENGTH| bytes of space in
/// |out|.
///
/// uint8_t *SHA1(const uint8_t *data, size_t len, uint8_t out[SHA_DIGEST_LENGTH]);
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `data` must be a valid pointer to an array of at least `len` bytes
/// - `out` must be a valid pointer to an array of at least `SHA_DIGEST_LENGTH` bytes
/// - The memory referenced by `data` must not be modified during the call
/// - The memory referenced by `out` must be properly aligned and not overlap with `data`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA1(data: *const u8, len: usize, out: *mut u8) -> *mut u8 {
    // Safety checks for null pointers
    if data.is_null() || out.is_null() {
        return out;
    }

    // Convert C pointers to Rust slices
    let input = unsafe { core::slice::from_raw_parts(data, len) };
    let output = unsafe { core::slice::from_raw_parts_mut(out, sha1::SHA1_DIGEST_LEN) };

    // Call fips_core's digest function with input and output buffer
    sha1::sha1_digest(input, output);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        // Test vector: SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let input = b"abc";
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];

        let mut output = [0u8; sha1::SHA1_DIGEST_LEN];

        unsafe {
            SHA1(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha1_incremental() {
        // Test vector: SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let input = b"abc";
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];

        let mut ctx = SHA_CTX::new();
        let mut output = [0u8; sha1::SHA1_DIGEST_LEN];

        unsafe {
            // Test the full sequence: Init -> Update -> Final
            let ctx_ptr = &mut ctx as *mut SHA_CTX;
            assert_eq!(SHA1_Init(ctx_ptr), 1);
            assert_eq!(
                SHA1_Update(
                    ctx_ptr,
                    input.as_ptr() as *const core::ffi::c_void,
                    input.len()
                ),
                1
            );
            assert_eq!(SHA1_Final(output.as_mut_ptr(), ctx_ptr), 1);
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha1_incremental_chunks() {
        // Test vector: SHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 84983e441c3bd26ebaae4aa1f95129e5e54670f1
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
            0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ];

        let mut ctx = SHA_CTX::new();
        let mut output = [0u8; sha1::SHA1_DIGEST_LEN];

        unsafe {
            // Initialize the context
            let ctx_ptr = &mut ctx as *mut SHA_CTX;
            assert_eq!(SHA1_Init(ctx_ptr), 1);

            // Update in chunks of 10 bytes
            for chunk in input.chunks(10) {
                assert_eq!(
                    SHA1_Update(
                        ctx_ptr,
                        chunk.as_ptr() as *const core::ffi::c_void,
                        chunk.len()
                    ),
                    1
                );
            }

            // Finalize
            assert_eq!(SHA1_Final(output.as_mut_ptr(), ctx_ptr), 1);
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha1_error_handling() {
        unsafe {
            // Test null pointers
            assert_eq!(SHA1_Init(std::ptr::null_mut()), 0);

            let mut ctx = SHA_CTX::new();
            let ctx_ptr = &mut ctx as *mut SHA_CTX;

            assert_eq!(SHA1_Update(ctx_ptr, std::ptr::null(), 10), 0);
            assert_eq!(
                SHA1_Update(
                    std::ptr::null_mut(),
                    b"test".as_ptr() as *const core::ffi::c_void,
                    4
                ),
                0
            );

            let mut output = [0u8; sha1::SHA1_DIGEST_LEN];
            assert_eq!(SHA1_Final(output.as_mut_ptr(), std::ptr::null_mut()), 0);
            assert_eq!(SHA1_Final(std::ptr::null_mut(), ctx_ptr), 0);
        }
    }

    #[test]
    fn test_sha1_empty_string() {
        // Test vector: SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let input = b"";
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];

        let mut output = [0u8; sha1::SHA1_DIGEST_LEN];

        unsafe {
            SHA1(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha1_long_string() {
        // Test vector: SHA1("The quick brown fox jumps over the lazy dog")
        // = 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
        let input = b"The quick brown fox jumps over the lazy dog";
        let expected = [
            0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
            0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
        ];

        let mut output = [0u8; sha1::SHA1_DIGEST_LEN];

        unsafe {
            SHA1(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        assert_eq!(output, expected);
    }
}
