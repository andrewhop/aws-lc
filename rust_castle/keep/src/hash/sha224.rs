//! SHA-224 hash function implementation.
//!
//! This is a no_std, no_alloc implementation with no external dependencies,
//! suitable for use in constrained environments including FIPS-validated modules.
//!
//! # Examples
//!
//! ```
//! use keep::hash::sha224;
//!
//! // One-shot hashing
//! let data = b"hello world";
//! let mut hash = [0u8; sha224::DIGEST_LEN];
//! sha224::digest(data, &mut hash);
//!
//! // Incremental hashing
//! let mut context = sha224::Context::new();
//! context.update(b"hello ");
//! context.update(b"world");
//! let mut hash = [0u8; sha224::DIGEST_LEN];
//! context.finalize(&mut hash);
//! ```

#[cfg(test)]
extern crate alloc;

/// The size of a SHA-224 digest in bytes (28 bytes = 224 bits)
pub const DIGEST_LEN: usize = 28;

/// The internal block size of SHA-224 in bytes (64 bytes = 512 bits)
pub const BLOCK_LEN: usize = 64;

/// Initial hash values for SHA-224
/// First 32 bits of the fractional parts of the square roots of the 9th through 16th primes 23..53
const H_INIT: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

// SHA-224 hash function context
#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct Context {
    /// Current hash state (h0-h7 in the pseudocode)
    h: [u32; 8],

    /// Lower 32 bits of bit count (OpenSSL compatibility)
    Nl: u32,

    /// Higher 32 bits of bit count (OpenSSL compatibility)
    Nh: u32,

    /// Unprocessed data buffer
    data: [u8; BLOCK_LEN],

    /// Number of bytes in the buffer
    num: u32,

    /// Length of the digest in bytes
    md_len: u32,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Creates a new SHA-224 context with the default initial state
    pub fn new() -> Self {
        Self {
            h: H_INIT,
            Nl: 0,
            Nh: 0,
            data: [0; BLOCK_LEN],
            num: 0,
            md_len: DIGEST_LEN as u32,
        }
    }

    /// Updates the hash state with input data
    pub fn update(&mut self, data: &[u8]) {
        super::sha2_common::update_hash_state(
            data,
            &mut self.h,
            &mut self.data,
            &mut self.num,
            &mut self.Nl,
            &mut self.Nh,
        );
    }

    /// Finalizes the hash computation and returns the digest
    pub fn finalize(mut self, output: &mut [u8]) {
        // assert!(output.len() >= DIGEST_LEN);

        // Use the common finalize function to process the padding and final block
        super::sha2_common::finalize_hash_state(
            &mut self.h,
            &mut self.data,
            &mut self.num,
            self.Nl,
            self.Nh,
        );

        // Convert state to bytes in big-endian format
        // For SHA-224, we only use the first 7 words (28 bytes) of the state
        for i in 0..7 {
            let bytes = self.h[i].to_be_bytes();
            output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
    }

    /// Resets the context to its initial state
    pub fn reset(&mut self) {
        self.h = H_INIT;
        self.data = [0; BLOCK_LEN];
        self.num = 0;
        self.Nl = 0;
        self.Nh = 0;
        self.md_len = DIGEST_LEN as u32;
    }
}

/// Computes the SHA-224 digest of the input data in one step
pub fn digest(data: &[u8], output: &mut [u8]) {
    let mut context = Context::new();
    context.update(data);
    context.finalize(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector structure for table-driven tests
    struct TestVector<'a> {
        input: &'a [u8],
        expected: [u8; DIGEST_LEN],
    }

    #[test]
    fn test_standard_vectors() {
        // Standard test vectors for SHA-224
        let test_vectors = [
            TestVector {
                input: &[],
                expected: [
                    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82,
                    0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f,
                ],
            },
            TestVector {
                input: b"abc",
                expected: [
                    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                    0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
                ],
            },
            TestVector {
                input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                expected: [
                    0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89,
                    0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25,
                ],
            },
            TestVector {
                input: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                expected: [
                    0xc9, 0x7c, 0xa9, 0xa5, 0x59, 0x85, 0x0c, 0xe9, 0x7a, 0x04, 0xa9, 0x6d, 0xef, 0x6d,
                    0x99, 0xa9, 0xe0, 0xe0, 0xe2, 0xab, 0x14, 0xe6, 0xb8, 0xdf, 0x26, 0x5f, 0xc0, 0xb3,
                ],
            },
        ];

        // Test each vector with both one-shot and incremental hashing
        for vector in &test_vectors {
            // Test one-shot hashing
            let mut result = [0u8; DIGEST_LEN];
            digest(vector.input, &mut result);
            assert_eq!(result, vector.expected);

            // Test incremental hashing (single update)
            let mut context = Context::new();
            context.update(vector.input);
            let mut result = [0u8; DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, vector.expected);

            test_incremental_patterns(vector.input, &vector.expected);
        }
    }

    // Helper function to test various incremental hashing patterns
    fn test_incremental_patterns(data: &[u8], expected: &[u8; DIGEST_LEN]) {
        // Test 1: Simple two-part split
        if data.len() > 1 {
            let split_point = data.len() / 2;
            let mut context = Context::new();
            context.update(&data[..split_point]);
            context.update(&data[split_point..]);
            let mut result = [0u8; DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 2: Every possible chunk size
        for chunk_size in 1..=data.len() {
            let mut context = Context::new();
            for chunk in data.chunks(chunk_size) {
                context.update(chunk);
            }
            let mut result = [0u8; DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 3: Alternating single byte and multi-byte updates
        if data.len() >= 16 {
            let mut context = Context::new();
            context.update(&data[0..1]); // 1 byte
            context.update(&data[1..5]); // 4 bytes
            context.update(&data[5..6]); // 1 byte
            context.update(&data[6..15]); // 9 bytes
            context.update(&data[15..16]); // 1 byte
            context.update(&data[16..]); // remaining bytes
            let mut result = [0u8; DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 4: Empty updates before, after, and between
        let mut context = Context::new();
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
        let mut result = [0u8; DIGEST_LEN];
        context.finalize(&mut result);
        assert_eq!(result, *expected);
    }

    #[test]
    fn test_million_a() {
        // Test with a million 'a' characters
        // This is a standard test vector for SHA-224
        // Expected hash: 20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67
        let expected = [
            0x20, 0x79, 0x46, 0x55, 0x98, 0x0c, 0x91, 0xd8, 0xbb, 0xb4, 0xc1, 0xea, 0x97, 0x61,
            0x8a, 0x4b, 0xf0, 0x3f, 0x42, 0x58, 0x19, 0x48, 0xb2, 0xee, 0x4e, 0xe7, 0xad, 0x67,
        ];

        // Create a context and update it with a million 'a' characters
        let mut context = Context::new();
        let chunk = [b'a'; 1000]; // 1000 'a' characters
        for _ in 0..1000 {
            // 1000 * 1000 = 1,000,000
            context.update(&chunk);
        }
        let mut result = [0u8; DIGEST_LEN];
        context.finalize(&mut result);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_context_reset() {
        let data1 = b"hello";
        let data2 = b"world";

        // First hash
        let mut context = Context::new();
        context.update(data1);

        // Reset and hash different data
        context.reset();
        context.update(data2);
        let mut result = [0u8; DIGEST_LEN];
        context.finalize(&mut result);

        // Compare with direct hash of second data
        let mut expected = [0u8; DIGEST_LEN];
        digest(data2, &mut expected);
        assert_eq!(result, expected);
    }
}
