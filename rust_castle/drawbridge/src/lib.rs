#[unsafe(no_mangle)]
pub extern "C" fn aws_lc_add_double(left: u64, right: u64) -> u64 {
    bailey::add_double(left, right)
}

#[unsafe(no_mangle)]
pub extern "C" fn aws_lc_add(left: u64, right: u64) -> u64 {
    bailey::add_double(left, right)
}

/// SHA256_CTX is a type alias for the keep::Context struct
#[allow(non_camel_case_types)]
pub type SHA256_CTX = keep::Context;

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

    sha.reset();

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
    let output = unsafe { core::slice::from_raw_parts_mut(out, keep::DIGEST_LEN) };

    // Finalize the hash and write to the output buffer
    // Note: finalize consumes the context, so we need to clone it
    let context = unsafe { &mut *sha };
    context.finalize(output);

    // Return 1 on success as per the C API
    1
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
    let output = unsafe { core::slice::from_raw_parts_mut(out, keep::DIGEST_LEN) };

    // Call Keep's digest function with input and output buffer
    keep::digest(input, output);

    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = aws_lc_add(2, 3);
        assert_eq!(result, 10);

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

        let mut output = [0u8; keep::DIGEST_LEN];

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

        let mut ctx = SHA256_CTX::new();
        let mut output = [0u8; keep::DIGEST_LEN];

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

        let mut ctx = SHA256_CTX::new();
        let mut output = [0u8; keep::DIGEST_LEN];

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

            let mut ctx = SHA256_CTX::new();
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

            let mut output = [0u8; keep::DIGEST_LEN];
            assert_eq!(SHA256_Final(output.as_mut_ptr(), std::ptr::null_mut()), 0);
            assert_eq!(SHA256_Final(std::ptr::null_mut(), ctx_ptr), 0);
        }
    }

    use super::*;

    /// Test vector structure for table-driven tests
    struct TestVector<'a> {
        input: &'a [u8],
        expected: [u8; keep::DIGEST_LEN],
    }

    #[test]
    fn test_standard_vectors() {
        // Combine all standard test vectors into a single table-driven test
        let test_vectors = [
            TestVector {
                input: &[],
                expected: [
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                    0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                    0x78, 0x52, 0xb8, 0x55,
                ],
            },
            TestVector {
                input: b"hello world",
                expected: [
                    0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
                    0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
                    0xe2, 0xef, 0xcd, 0xe9,
                ],
            },
            TestVector {
                input: b"abc",
                expected: [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                    0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                    0xf2, 0x00, 0x15, 0xad,
                ],
            },
            TestVector {
                input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                expected: [
                    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                    0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                    0x19, 0xdb, 0x06, 0xc1,
                ],
            },
            TestVector {
                input: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                expected: [
                    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04,
                    0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03,
                    0x7a, 0xfe, 0xe9, 0xd1,
                ],
            },
        ];

        // Test each vector with both one-shot and incremental hashing
        for vector in &test_vectors {
            // Test one-shot hashing
            let mut result = [0u8; keep::DIGEST_LEN];
            keep::digest(vector.input, &mut result);
            assert_eq!(result, vector.expected);

            // Test incremental hashing (single update)
            let mut context = keep::Context::new();
            context.update(vector.input);
            let mut result = [0u8; keep::DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, vector.expected);

            test_incremental_patterns(vector.input, &vector.expected);
        }
    }

    // Helper function to test various incremental hashing patterns
    fn test_incremental_patterns(data: &[u8], expected: &[u8; keep::DIGEST_LEN]) {
        // Test 1: Simple two-part split
        if data.len() > 1 {
            let split_point = data.len() / 2;
            let mut context = keep::Context::new();
            context.update(&data[..split_point]);
            context.update(&data[split_point..]);
            let mut result = [0u8; keep::DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 2: Every possible chunk size
        for chunk_size in 1..=data.len() {
            let mut context = keep::Context::new();
            for chunk in data.chunks(chunk_size) {
                context.update(chunk);
            }
            let mut result = [0u8; keep::DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 3: Alternating single byte and multi-byte updates
        if data.len() >= 16 {
            let mut context = keep::Context::new();
            context.update(&data[0..1]); // 1 byte
            context.update(&data[1..5]); // 4 bytes
            context.update(&data[5..6]); // 1 byte
            context.update(&data[6..15]); // 9 bytes
            context.update(&data[15..16]); // 1 byte
            context.update(&data[16..]); // remaining bytes
            let mut result = [0u8; keep::DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 4: Decreasing size updates
        if data.len() >= 3 {
            let mut context = keep::Context::new();
            let len = data.len();
            let third = len / 3;
            context.update(&data[0..third * 2]);
            context.update(&data[third * 2..third * 2 + third / 2]);
            context.update(&data[third * 2 + third / 2..]);
            let mut result = [0u8; keep::DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 5: Empty updates before, after, and between
        let mut context = keep::Context::new();
        context.update(&[]); // Empty update before
        if data.len() > 1 {
            let mid = data.len() / 2;
            context.update(&data[..mid]);
            context.update(&[]); // Empty update in the middle
            context.update(&data[mid..]);
        } else {
            context.update(data);
        }
        context.update(&[]); // Empty update after
        let mut result = [0u8; keep::DIGEST_LEN];
        context.finalize(&mut result);
        assert_eq!(result, *expected);
    }

    #[test]
    fn test_boundaries() {
        // Combine block boundaries and padding edge cases tests
        let block_size = keep::BLOCK_LEN;

        // Test cases for different boundary conditions
        let test_sizes = [
            // Block boundaries
            block_size,     // Exactly one block
            block_size * 2, // Exactly two blocks
            // Padding edge cases
            55, // Just below padding boundary
            56, // At padding boundary
            57, // Just above padding boundary
            // Additional interesting sizes
            block_size - 1, // One byte less than a block
            block_size + 1, // One byte more than a block
        ];

        for &size in &test_sizes {
            // Use a consistent byte value based on the size
            let byte_value = (size % 256) as u8;
            let data = vec![byte_value; size];

            // Test direct hashing
            let mut direct_result = [0u8; keep::DIGEST_LEN];
            keep::digest(&data, &mut direct_result);

            // Test incremental hashing
            let mut context = keep::Context::new();
            context.update(&data);
            let mut incremental_result = [0u8; keep::DIGEST_LEN];
            context.finalize(&mut incremental_result);

            assert_eq!(direct_result, incremental_result);

            // For larger sizes, also test with multiple updates
            if size > 10 {
                let mut context = keep::Context::new();
                let chunk_size = size / 3;
                for chunk in data.chunks(chunk_size) {
                    context.update(chunk);
                }
                let mut multi_update_result = [0u8; keep::DIGEST_LEN];
                context.finalize(&mut multi_update_result);

                assert_eq!(direct_result, multi_update_result);
            }
        }
    }

    #[test]
    fn test_million_a() {
        // Test with a million 'a' characters
        // This is a standard test vector for SHA-256
        // Expected hash: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
        let expected = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];

        // Create a context and update it with a million 'a' characters
        let mut context = keep::Context::new();
        let chunk = [b'a'; 1000]; // 1000 'a' characters
        for _ in 0..1000 {
            // 1000 * 1000 = 1,000,000
            context.update(&chunk);
        }
        let mut result = [0u8; keep::DIGEST_LEN];
        context.finalize(&mut result);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_context_reset() {
        let data1 = b"hello";
        let data2 = b"world";

        // First hash
        let mut context = keep::Context::new();
        context.update(data1);

        // Reset and hash different data
        context.reset();
        context.update(data2);
        let mut result = [0u8; keep::DIGEST_LEN];
        context.finalize(&mut result);

        // Compare with direct hash of second data
        let mut expected = [0u8; keep::DIGEST_LEN];
        keep::digest(data2, &mut expected);
        assert_eq!(result, expected);
    }
}
