use crate::digest::{Digest, sha2};

/// SHA256_CTX is a type alias for the sha2::Context struct
#[allow(non_camel_case_types)]
pub type SHA256_CTX = sha2::SHA256;
#[allow(non_camel_case_types)]
pub type SHA224_CTX = sha2::SHA224;

/// SHA256_Init initialises |sha| and returns 1.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA256_CTX` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256_Init(sha: *mut SHA256_CTX) -> i32 {
    if sha.is_null() {
        return 0;
    }
    let sha = unsafe { &mut *sha };

    // Initialize as SHA-256
    sha.init();

    // Return 1 on success as per the C API
    1
}

/// SHA256_Update adds |len| bytes from |data| to |sha| and returns 1.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA256_CTX` struct
/// - `data` must be a valid pointer to an array of at least `len` bytes
/// - The memory referenced by `data` must not be modified during the call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256_Update(
    sha: *mut SHA256_CTX,
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

/// SHA256_Final adds the final padding to |sha| and writes the resulting digest
/// to |out|, which must have at least |SHA256_DIGEST_LENGTH| bytes of space. It
/// returns one on success and zero on programmer error.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA256_CTX` struct
/// - `out` must be a valid pointer to an array of at least `SHA256_DIGEST_LENGTH` bytes
/// - The memory referenced by `out` must be properly aligned
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256_Final(out: *mut u8, sha: *mut SHA256_CTX) -> i32 {
    if sha.is_null() || out.is_null() {
        return 0;
    }

    // Create a mutable slice for the output buffer
    let output = unsafe { core::slice::from_raw_parts_mut(out, sha2::SHA256_DIGEST_LEN) };

    // Finalize the hash and write to the output buffer using the SHA-256 specific method
    let context = unsafe { &mut *sha };
    context.finalize(output);

    // Return 1 on success as per the C API
    1
}

/// SHA224_Init initialises |sha| and returns 1.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA256_CTX` struct (which is used for SHA224 in the C API)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA224_Init(sha: *mut SHA224_CTX) -> i32 {
    if sha.is_null() {
        return 0;
    }

    // Initialize the context with SHA-224 parameters
    let sha_ctx = unsafe { &mut *sha };
    sha_ctx.init();

    // Return 1 on success as per the C API
    1
}

/// SHA224_Update adds |len| bytes from |data| to |sha| and returns 1.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA256_CTX` struct (which is used for SHA224 in the C API)
/// - `data` must be a valid pointer to an array of at least `len` bytes
/// - The memory referenced by `data` must not be modified during the call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA224_Update(
    sha: *mut SHA224_CTX,
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

/// SHA224_Final adds the final padding to |sha| and writes the resulting digest
/// to |out|, which must have at least |SHA224_DIGEST_LENGTH| bytes of space. It
/// returns one on success and zero on programmer error.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `sha` must be a valid pointer to a `SHA256_CTX` struct (which is used for SHA224 in the C API)
/// - `out` must be a valid pointer to an array of at least `SHA224_DIGEST_LENGTH` bytes
/// - The memory referenced by `out` must be properly aligned
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA224_Final(out: *mut u8, sha: *mut SHA224_CTX) -> i32 {
    if sha.is_null() || out.is_null() {
        return 0;
    }

    // Create a mutable slice for the output buffer
    let output = unsafe { core::slice::from_raw_parts_mut(out, sha2::SHA224_DIGEST_LEN) };

    // Finalize the hash and write to the output buffer using the SHA-224 specific method
    let context = unsafe { &mut *sha };
    context.finalize(output);

    // Return 1 on success as per the C API
    1
}

/// SHA224 writes the digest of |len| bytes from |data| to |out| and returns
/// |out|. There must be at least |SHA224_DIGEST_LENGTH| bytes of space in
/// |out|.
///
/// uint8_t *SHA224(const uint8_t *data, size_t len, uint8_t out[SHA224_DIGEST_LENGTH]);
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `data` must be a valid pointer to an array of at least `len` bytes
/// - `out` must be a valid pointer to an array of at least `SHA224_DIGEST_LENGTH` bytes
/// - The memory referenced by `data` must not be modified during the call
/// - The memory referenced by `out` must be properly aligned and not overlap with `data`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA224(data: *const u8, len: usize, out: *mut u8) -> *mut u8 {
    // Safety checks for null pointers
    if data.is_null() || out.is_null() {
        return out;
    }

    // Convert C pointers to Rust slices
    let input = unsafe { core::slice::from_raw_parts(data, len) };
    let output = unsafe { core::slice::from_raw_parts_mut(out, sha2::SHA224_DIGEST_LEN) };

    // Call fips_core's digest function with input and output buffer
    sha2::sha224_digest(input, output);

    out
}

/// SHA256 writes the digest of |len| bytes from |data| to |out| and returns
/// |out|. There must be at least |SHA256_DIGEST_LENGTH| bytes of space in
/// |out|.
///
/// uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LENGTH]);
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
    let output = unsafe { core::slice::from_raw_parts_mut(out, sha2::SHA256_DIGEST_LEN) };

    // Call fips_core's digest function with input and output buffer
    sha2::sha256_digest(input, output);

    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        // Test vector: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let input = b"abc";
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let mut output = [0u8; sha2::SHA256_DIGEST_LEN];

        unsafe {
            SHA256(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha256_incremental() {
        // Test vector: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let input = b"abc";
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let mut ctx = SHA256_CTX::default();
        let mut output = [0u8; sha2::SHA256_DIGEST_LEN];

        unsafe {
            // Test the full sequence: Init -> Update -> Final
            let ctx_ptr = &mut ctx as *mut SHA256_CTX;
            assert_eq!(SHA256_Init(ctx_ptr), 1);
            assert_eq!(
                SHA256_Update(
                    ctx_ptr,
                    input.as_ptr() as *const core::ffi::c_void,
                    input.len()
                ),
                1
            );
            assert_eq!(SHA256_Final(output.as_mut_ptr(), ctx_ptr), 1);
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha256_incremental_chunks() {
        // Test vector: SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];

        let mut ctx = SHA256_CTX::default();
        let mut output = [0u8; sha2::SHA256_DIGEST_LEN];

        unsafe {
            // Initialize the context
            let ctx_ptr = &mut ctx as *mut SHA256_CTX;
            assert_eq!(SHA256_Init(ctx_ptr), 1);

            // Update in chunks of 10 bytes
            for chunk in input.chunks(10) {
                assert_eq!(
                    SHA256_Update(
                        ctx_ptr,
                        chunk.as_ptr() as *const core::ffi::c_void,
                        chunk.len()
                    ),
                    1
                );
            }

            // Finalize
            assert_eq!(SHA256_Final(output.as_mut_ptr(), ctx_ptr), 1);
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha256_error_handling() {
        unsafe {
            // Test null pointers
            assert_eq!(SHA256_Init(std::ptr::null_mut()), 0);

            let mut ctx = SHA256_CTX::default();
            let ctx_ptr = &mut ctx as *mut SHA256_CTX;

            assert_eq!(SHA256_Update(ctx_ptr, std::ptr::null(), 10), 0);
            assert_eq!(
                SHA256_Update(
                    std::ptr::null_mut(),
                    b"test".as_ptr() as *const core::ffi::c_void,
                    4
                ),
                0
            );

            let mut output = [0u8; sha2::SHA256_DIGEST_LEN];
            assert_eq!(SHA256_Final(output.as_mut_ptr(), std::ptr::null_mut()), 0);
            assert_eq!(SHA256_Final(std::ptr::null_mut(), ctx_ptr), 0);
        }
    }

    #[test]
    fn test_sha224() {
        // Test vector: SHA224("abc") = 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
        let input = b"abc";
        let expected = [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
            0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
        ];

        let mut output = [0u8; sha2::SHA224_DIGEST_LEN];

        unsafe {
            SHA224(input.as_ptr(), input.len(), output.as_mut_ptr());
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha224_incremental() {
        // Test vector: SHA224("abc") = 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
        let input = b"abc";
        let expected = [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
            0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
        ];

        let mut ctx = SHA224_CTX::default();
        let mut output = [0u8; sha2::SHA224_DIGEST_LEN];

        unsafe {
            // Test the full sequence: Init -> Update -> Final
            let ctx_ptr = &mut ctx as *mut SHA224_CTX;
            assert_eq!(SHA224_Init(ctx_ptr), 1);
            assert_eq!(
                SHA224_Update(
                    ctx_ptr,
                    input.as_ptr() as *const core::ffi::c_void,
                    input.len()
                ),
                1
            );
            assert_eq!(SHA224_Final(output.as_mut_ptr(), ctx_ptr), 1);
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha224_incremental_chunks() {
        // Test vector: SHA224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 75388b16512776cc5dba5da1fd890150b0c6455cb4f58b19525225
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        // Expected hash for "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let expected = [
            0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89,
            0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25,
        ];

        let mut ctx = SHA224_CTX::default();
        let mut output = [0u8; sha2::SHA224_DIGEST_LEN];

        unsafe {
            // Initialize the context
            let ctx_ptr = &mut ctx as *mut SHA224_CTX;
            assert_eq!(SHA224_Init(ctx_ptr), 1);

            // Update in chunks of 10 bytes
            for chunk in input.chunks(10) {
                assert_eq!(
                    SHA224_Update(
                        ctx_ptr,
                        chunk.as_ptr() as *const core::ffi::c_void,
                        chunk.len()
                    ),
                    1
                );
            }

            // Finalize
            assert_eq!(SHA224_Final(output.as_mut_ptr(), ctx_ptr), 1);
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_sha224_error_handling() {
        unsafe {
            // Test null pointers
            assert_eq!(SHA224_Init(std::ptr::null_mut()), 0);

            let mut ctx = SHA224_CTX::default();
            let ctx_ptr = &mut ctx as *mut SHA224_CTX;

            assert_eq!(SHA224_Update(ctx_ptr, std::ptr::null(), 10), 0);
            assert_eq!(
                SHA224_Update(
                    std::ptr::null_mut(),
                    b"test".as_ptr() as *const core::ffi::c_void,
                    4
                ),
                0
            );

            let mut output = [0u8; sha2::SHA224_DIGEST_LEN];
            assert_eq!(SHA224_Final(output.as_mut_ptr(), std::ptr::null_mut()), 0);
            assert_eq!(SHA224_Final(std::ptr::null_mut(), ctx_ptr), 0);
        }
    }
}
