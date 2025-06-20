//! SHA-1 hash function implementation.
//!
//! This is a no_std, no_alloc implementation with no external dependencies,
//! suitable for use in constrained environments including FIPS-validated modules.
//!
//! # Examples
//!
//! ```
//! use fips_core::digest::sha1;
//!
//! // SHA-1 one-shot hashing
//! let data = b"hello world";
//! let mut hash = [0u8; sha1::SHA1_DIGEST_LEN];
//! sha1::sha1_digest(data, &mut hash);
//!
//! // SHA-1 incremental hashing
//! let mut state = sha1::State::new();
//! state.update(b"hello ");
//! state.update(b"world");
//! let mut hash = [0u8; sha1::SHA1_DIGEST_LEN];
//! state.finalize(&mut hash);
//! ```

use crate::digest::Digest;

#[cfg(test)]
extern crate alloc;

/// The size of a SHA-1 digest in bytes (20 bytes = 160 bits)
pub const SHA1_DIGEST_LEN: usize = 20;

/// The internal block size of SHA-1 in bytes (64 bytes = 512 bits)
pub const BLOCK_LEN: usize = 64;

/// Initial hash values for SHA-1
const SHA1_H_INIT: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Round constants for SHA-1
const K: [u32; 4] = [
    0x5A827999, // 0 <= i <= 19
    0x6ED9EBA1, // 20 <= i <= 39
    0x8F1BBCDC, // 40 <= i <= 59
    0xCA62C1D6, // 60 <= i <= 79
];

/// Padding byte (binary 10000000)
const PADDING_BYTE: u8 = 0x80;

/// Padding zero byte
const PADDING_ZERO: u8 = 0x00;

/// SHA-1 hash function state
#[repr(C)]
pub struct State {
    /// Current hash state (h0-h4 in the pseudocode)
    h: [u32; 5],

    /// Lower 32 bits of bit count (OpenSSL compatibility)
    Nl: u32,

    /// Higher 32 bits of bit count (OpenSSL compatibility)
    Nh: u32,

    /// Unprocessed data buffer
    data: [u8; BLOCK_LEN],

    /// Number of bytes in the buffer
    num: u32,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// Creates a new SHA-1 context with the default initial state
    pub fn new() -> Self {
        Self {
            h: SHA1_H_INIT,
            Nl: 0,
            Nh: 0,
            data: [0; BLOCK_LEN],
            num: 0,
        }
    }

    /// Resets the context to its initial state
    pub fn reset(&mut self) {
        self.h = SHA1_H_INIT;
        self.data = [0; BLOCK_LEN];
        self.num = 0;
        self.Nl = 0;
        self.Nh = 0;
    }
}

impl Digest for State {
    fn init(&mut self) {
        self.h = SHA1_H_INIT;
        self.data = [0; BLOCK_LEN];
        self.num = 0;
        self.Nl = 0;
        self.Nh = 0;
    }

    fn update(&mut self, data: &[u8]) {
        let h: &mut [u32; 5] = &mut self.h;
        let buffer: &mut [u8; 64] = &mut self.data;
        let num: &mut u32 = &mut self.num;
        let nl: &mut u32 = &mut self.Nl;
        let nh: &mut u32 = &mut self.Nh;

        // Update the total bit count
        let bits = (data.len() as u64) * 8;
        let new_nl = nl.wrapping_add((bits & 0xFFFF_FFFF) as u32);

        // Check for overflow
        if new_nl < *nl {
            *nh = nh.wrapping_add(1); // Carry to high word
        }
        *nl = new_nl;

        // Add high bits
        *nh = nh.wrapping_add((bits >> 32) as u32);

        // Process the input data
        let mut data_index = 0;

        // If we have data in the buffer, try to fill it first
        if *num > 0 {
            // Calculate how many bytes we can copy to fill the buffer
            let bytes_to_copy = core::cmp::min(64 - *num as usize, data.len());

            // Copy bytes to the buffer
            buffer[*num as usize..*num as usize + bytes_to_copy]
                .copy_from_slice(&data[..bytes_to_copy]);

            *num += bytes_to_copy as u32;
            data_index = bytes_to_copy;

            // If the buffer is full, process it
            if *num as usize == 64 {
                process_block(buffer, h);
                *num = 0;
            }
        }

        // Process as many complete blocks as possible
        while data_index + 64 <= data.len() {
            buffer.copy_from_slice(&data[data_index..data_index + 64]);
            process_block(buffer, h);
            data_index += 64;
        }

        // Store any remaining bytes in the buffer
        if data_index < data.len() {
            let remaining = data.len() - data_index;
            buffer[*num as usize..*num as usize + remaining].copy_from_slice(&data[data_index..]);
            *num += remaining as u32;
        }
    }

    fn finalize(&mut self, out: &mut [u8]) {
        finalize_hash_state(&mut self.h, &mut self.data, &mut self.num, self.Nl, self.Nh);

        // Convert the hash state to bytes (big-endian)
        for i in 0..5 {
            let bytes = self.h[i].to_be_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
    }
}

/// Computes the SHA-1 digest of the input data in one step
pub fn sha1_digest(data: &[u8], output: &mut [u8]) {
    let mut context = State::new();
    context.update(data);
    context.finalize(output);
}

/// Left rotate a 32-bit value by the specified number of bits
#[inline(always)]
const fn leftrotate(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

/// Common finalize function for SHA-1
/// Returns the final hash state after padding and processing
fn finalize_hash_state(h: &mut [u32; 5], buffer: &mut [u8; 64], num: &mut u32, nl: u32, nh: u32) {
    // Pad the message
    // 1. Append a single '1' bit
    buffer[*num as usize] = PADDING_BYTE;
    *num += 1;

    // 2. Append '0' bits until the message length is congruent to 448 modulo 512
    if (*num as usize) > 64 - 8 {
        // Not enough room for the length, pad with zeros and process this block
        while (*num as usize) < 64 {
            buffer[*num as usize] = PADDING_ZERO;
            *num += 1;
        }
        process_block(buffer, h);
        *num = 0;
    }

    // Pad with zeros up to the point where the length will be added
    while (*num as usize) < 64 - 8 {
        buffer[*num as usize] = PADDING_ZERO;
        *num += 1;
    }

    // 3. Append the length as a 64-bit big-endian integer
    let bit_len_bytes = [
        (nh >> 24) as u8,
        (nh >> 16) as u8,
        (nh >> 8) as u8,
        nh as u8,
        (nl >> 24) as u8,
        (nl >> 16) as u8,
        (nl >> 8) as u8,
        nl as u8,
    ];
    buffer[*num as usize..*num as usize + 8].copy_from_slice(&bit_len_bytes);

    // Process the final block
    process_block(buffer, h);
}

/// Process a complete 64-byte block with the SHA-1 compression function
fn process_block(data: &[u8; 64], state: &mut [u32; 5]) {
    // Initialize hash value for this chunk
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    // Message schedule: 80 32-bit words
    let mut w = [0u32; 80];

    // Break chunk into sixteen 32-bit big-endian words
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
    }

    // Extend the sixteen 32-bit words into eighty 32-bit words
    for i in 16..80 {
        w[i] = leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    // Main loop
    for i in 0..80 {
        let f: u32;
        let k: u32;

        if i < 20 {
            f = (b & c) | ((!b) & d);
            k = K[0];
        } else if i < 40 {
            f = b ^ c ^ d;
            k = K[1];
        } else if i < 60 {
            f = (b & c) | (b & d) | (c & d);
            k = K[2];
        } else {
            f = b ^ c ^ d;
            k = K[3];
        }

        let temp = leftrotate(a, 5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = leftrotate(b, 30);
        b = a;
        a = temp;
    }

    // Add this chunk's hash to result so far
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_sha1_standard_vectors() {
        // Test vectors for SHA-1
        let empty_data: &[u8] = &[];
        let fox_data: &[u8] = b"The quick brown fox jumps over the lazy dog";

        let test_vectors = [
            (
                empty_data,
                [
                    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95,
                    0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
                ],
            ),
            (
                fox_data,
                [
                    0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb,
                    0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
                ],
            ),
        ];

        // Test each vector with both one-shot and incremental hashing
        for (input, expected) in &test_vectors {
            // Test one-shot hashing
            let mut result = [0u8; SHA1_DIGEST_LEN];
            sha1_digest(input, &mut result);
            assert_eq!(result, *expected);

            // Test incremental hashing (single update)
            let mut context = State::new();
            context.update(input);
            let mut result = [0u8; SHA1_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);

            test_sha1_incremental_patterns(input, expected);
        }
    }

    // Helper function to test various incremental hashing patterns for SHA-1
    fn test_sha1_incremental_patterns(data: &[u8], expected: &[u8; SHA1_DIGEST_LEN]) {
        // Test 1: Simple two-part split
        if data.len() > 1 {
            let split_point = data.len() / 2;
            let mut context = State::new();
            context.update(&data[..split_point]);
            context.update(&data[split_point..]);
            let mut result = [0u8; SHA1_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 2: Every possible chunk size
        for chunk_size in 1..=data.len() {
            let mut context = State::new();
            for chunk in data.chunks(chunk_size) {
                context.update(chunk);
            }
            let mut result = [0u8; SHA1_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 3: Alternating single byte and multi-byte updates
        if data.len() >= 16 {
            let mut context = State::new();
            context.update(&data[0..1]); // 1 byte
            context.update(&data[1..5]); // 4 bytes
            context.update(&data[5..6]); // 1 byte
            context.update(&data[6..15]); // 9 bytes
            context.update(&data[15..16]); // 1 byte
            context.update(&data[16..]); // remaining bytes
            let mut result = [0u8; SHA1_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 4: Empty updates before, after, and between
        let empty_data: &[u8] = &[];
        let mut context = State::new();
        context.update(empty_data); // Empty update before
        if data.len() > 1 {
            let mid = data.len() / 2;
            context.update(&data[..mid]);
            context.update(empty_data); // Empty update in the middle
            context.update(&data[mid..]);
        } else {
            context.update(data);
        }
        context.update(empty_data); // Empty update after
        let mut result = [0u8; SHA1_DIGEST_LEN];
        context.finalize(&mut result);
        assert_eq!(result, *expected);
    }

    #[test]
    fn test_sha1_additional_vectors() {
        // Additional test vectors for SHA-1
        let test_vectors = [
            (
                b"abc" as &[u8],
                [
                    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
                    0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
                ],
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" as &[u8],
                [
                    0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9,
                    0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
                ],
            ),
        ];

        for (input, expected) in &test_vectors {
            let mut result = [0u8; SHA1_DIGEST_LEN];
            sha1_digest(input, &mut result);
            assert_eq!(result, *expected);
        }
    }

    #[test]
    fn test_sha1_million_a() {
        // Test with a million 'a' characters
        // Expected hash: 34aa973cd4c4daa4f61eeb2bdbad27316534016f
        let expected = [
            0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
            0x27, 0x31, 0x65, 0x34, 0x01, 0x6f,
        ];

        // Create a context and update it with a million 'a' characters
        let mut context = State::new();
        let chunk = [b'a'; 1000]; // 1000 'a' characters
        for _ in 0..1000 {
            // 1000 * 1000 = 1,000,000
            context.update(&chunk);
        }
        let mut result = [0u8; SHA1_DIGEST_LEN];
        context.finalize(&mut result);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_context_reset() {
        // Test SHA-1 reset
        let data1 = b"hello";
        let data2 = b"world";

        // First hash
        let mut context = State::new();
        context.update(data1);

        // Reset and hash different data
        context.reset();
        context.update(data2);
        let mut result = [0u8; SHA1_DIGEST_LEN];
        context.finalize(&mut result);

        // Compare with direct hash of second data
        let mut expected = [0u8; SHA1_DIGEST_LEN];
        sha1_digest(data2, &mut expected);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_boundaries() {
        // Combine block boundaries and padding edge cases tests
        let block_size = BLOCK_LEN;

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
            let mut direct_result = [0u8; SHA1_DIGEST_LEN];
            sha1_digest(&data, &mut direct_result);

            // Test incremental hashing
            let mut context = State::new();
            context.update(&data);
            let mut incremental_result = [0u8; SHA1_DIGEST_LEN];
            context.finalize(&mut incremental_result);

            assert_eq!(direct_result, incremental_result);
        }
    }
}
