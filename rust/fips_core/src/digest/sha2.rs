//! SHA-2 hash function implementations (SHA-224 and SHA-256).
//!
//! This is a no_std, no_alloc implementation with no external dependencies,
//! suitable for use in constrained environments including FIPS-validated modules.
//!
//! # Examples
//!
//! ```
//! use fips_core::digest::Digest;
//! use fips_core::digest::sha2::{SHA224, SHA256, SHA224_DIGEST_LEN, SHA256_DIGEST_LEN};
//!
//! // SHA-256 using the Digest trait
//! let data = b"hello world";
//! let mut sha256 = SHA256::new();
//! sha256.update(data);
//! let mut hash = [0u8; SHA256_DIGEST_LEN];
//! sha256.finalize(&mut hash);
//!
//! // SHA-224 using the Digest trait
//! let data = b"hello world";
//! let mut sha224 = SHA224::new();
//! sha224.update(data);
//! let mut hash = [0u8; SHA224_DIGEST_LEN];
//! sha224.finalize(&mut hash);
//! ```
//!
//! # Examples
//!
//! ```
//! use fips_core::hash::sha2;
//!
//! // SHA-256 one-shot hashing
//! let data = b"hello world";
//! let mut hash = [0u8; sha2::SHA256_DIGEST_LEN];
//! sha2::sha256_digest(data, &mut hash);
//!
//! // SHA-256 incremental hashing
//! let mut context = sha2::Context::new_sha256();
//! context.update(b"hello ");
//! context.update(b"world");
//! let mut hash = [0u8; sha2::SHA256_DIGEST_LEN];
//! context.sha256_finalize(&mut hash);
//!
//! // SHA-224 one-shot hashing
//! let data = b"hello world";
//! let mut hash = [0u8; sha2::SHA224_DIGEST_LEN];
//! sha2::sha224_digest(data, &mut hash);
//!
//! // SHA-224 incremental hashing
//! let mut context = sha2::Context::new_sha224();
//! context.update(b"hello ");
//! context.update(b"world");
//! let mut hash = [0u8; sha2::SHA224_DIGEST_LEN];
//! context.sha224_finalize(&mut hash);
//! ```

#[cfg(test)]
extern crate alloc;

use crate::digest::Digest;

/// The size of a SHA-256 digest in bytes (32 bytes = 256 bits)
pub const SHA256_DIGEST_LEN: usize = 32;

/// The size of a SHA-224 digest in bytes (28 bytes = 224 bits)
pub const SHA224_DIGEST_LEN: usize = 28;

/// The internal block size of SHA-2 in bytes (64 bytes = 512 bits)
pub const BLOCK_LEN: usize = 64;

/// Initial hash values for SHA-256: first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
const SHA256_H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Initial hash values for SHA-224: first 32 bits of the fractional parts of the square roots of the 9th through 16th primes 23..53
const SHA224_H_INIT: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

// SHA-2 hash function context
#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[allow(non_snake_case)]
struct Sha2State {
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

impl Sha2State {
    /// Updates the hash state with input data
    fn update(&mut self, data: &[u8]) {
        let h: &mut [u32; 8] = &mut self.h;
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
    /// Common finalize function for SHA-224 and SHA-256
    /// Returns the final hash state after padding and processing
    fn finalize_hash_state(&mut self) {
        let h: &mut [u32; 8] = &mut self.h;
        let buffer: &mut [u8; 64] = &mut self.data;
        let num: &mut u32 = &mut self.num;
        let nl: &mut u32 = &mut self.Nl;
        let nh: &mut u32 = &mut self.Nh;
        //&mut this.h, &mut this.data, &mut this.num, this.Nl, this.Nh
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
            (*nh >> 24) as u8,
            (*nh >> 16) as u8,
            (*nh >> 8) as u8,
            *nh as u8,
            (*nl >> 24) as u8,
            (*nl >> 16) as u8,
            (*nl >> 8) as u8,
            *nl as u8,
        ];
        buffer[*num as usize..*num as usize + 8].copy_from_slice(&bit_len_bytes);

        // Process the final block
        process_block(buffer, h);
    }
}

/// SHA-224 hash function implementation
#[derive(Clone, Copy, Debug)]
pub struct SHA224 {
    state: Sha2State,
}

impl Default for SHA224 {
    fn default() -> Self {
        SHA224 {
            state: Sha2State {
                h: SHA224_H_INIT,
                Nl: 0,
                Nh: 0,
                data: [0; BLOCK_LEN],
                num: 0,
                md_len: SHA224_DIGEST_LEN as u32,
            },
        }
    }
}

impl Digest for SHA224 {
    fn init(&mut self) {
        let this = &mut self.state;
        this.md_len = SHA224_DIGEST_LEN as u32;
        this.h = SHA224_H_INIT;
        this.data = [0; BLOCK_LEN];
        this.num = 0;
        this.Nl = 0;
        this.Nh = 0;
    }

    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn finalize(&mut self, out: &mut [u8]) {
        let this = &mut self.state;
        this.finalize_hash_state();
        // For SHA-224, we only use the first 7 words (28 bytes)
        for i in 0..7 {
            let bytes = this.h[i].to_be_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
    }
}

/// SHA-256 hash function implementation
#[derive(Clone, Copy, Debug)]
pub struct SHA256 {
    state: Sha2State,
}

impl Default for SHA256 {
    fn default() -> Self {
        SHA256 {
            state: Sha2State {
                h: SHA256_H_INIT,
                Nl: 0,
                Nh: 0,
                data: [0; BLOCK_LEN],
                num: 0,
                md_len: SHA256_DIGEST_LEN as u32,
            },
        }
    }
}

impl Digest for SHA256 {
    fn init(&mut self) {
        let this = &mut self.state;
        this.md_len = SHA256_DIGEST_LEN as u32;
        this.h = SHA256_H_INIT;
        this.data = [0; BLOCK_LEN];
        this.num = 0;
        this.Nl = 0;
        this.Nh = 0;
    }

    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn finalize(&mut self, out: &mut [u8]) {
        let this = &mut self.state;
        this.finalize_hash_state();
        // For SHA-256, we use all 8 words (32 bytes)
        for i in 0..8 {
            let bytes = this.h[i].to_be_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
    }
}

/// Computes the SHA-256 digest of the input data in one step
pub fn sha256_digest(data: &[u8], output: &mut [u8]) {
    let mut context = SHA256::default();
    context.update(data);
    context.finalize(output);
}

/// Computes the SHA-224 digest of the input data in one step
pub fn sha224_digest(data: &[u8], output: &mut [u8]) {
    let mut context = SHA224::default();
    context.update(data);
    context.finalize(output);
}

/// Padding byte (binary 10000000)
const PADDING_BYTE: u8 = 0x80;

/// Padding zero byte
const PADDING_ZERO: u8 = 0x00;

/// Round constants K[0..63]
/// First 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Right rotate a 32-bit value by the specified number of bits
#[inline(always)]
const fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Choose function: (x & y) ^ (!x & z)
/// If x then y else z
#[inline(always)]
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Majority function: (x & y) ^ (x & z) ^ (y & z)
/// Returns the bit value that appears most often in x, y, z
#[inline(always)]
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Sigma0 function: rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
/// Used in the compression function for working variables
#[inline(always)]
const fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Sigma1 function: rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
/// Used in the compression function for working variables
#[inline(always)]
const fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Small sigma0 function: rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
/// Used in message schedule array preparation
#[inline(always)]
const fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Small sigma1 function: rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
/// Used in message schedule array preparation
#[inline(always)]
const fn small_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// Macro for first 16 rounds (optimized)
macro_rules! round_00_15 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr, $i:expr) => {
        // Combine operations to reduce temporary variables
        let temp1 = $h
            .wrapping_add(sigma1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add(K[$i])
            .wrapping_add($w[$i]);
        let temp2 = sigma0($a).wrapping_add(maj($a, $b, $c));

        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(temp1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = temp1.wrapping_add(temp2);
    };
}

// Macro for rounds 16-63 (optimized)
macro_rules! round_16_63 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $w:expr, $i:expr) => {
        // Update message schedule - optimized to reduce temporary variables
        $w[$i & 0x0f] = $w[($i - 16) & 0x0f]
            .wrapping_add(small_sigma0($w[($i - 15) & 0x0f]))
            .wrapping_add($w[($i - 7) & 0x0f])
            .wrapping_add(small_sigma1($w[($i - 2) & 0x0f]));

        // Process round - optimized to reduce temporary variables
        let temp1 = $h.wrapping_add(sigma1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add(K[$i])
            .wrapping_add($w[$i & 0x0f]);
        let temp2 = sigma0($a).wrapping_add(maj($a, $b, $c));

        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(temp1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = temp1.wrapping_add(temp2);
    };
}

/// Process a complete 64-byte block with the SHA-2 compression function
/// This is the core algorithm shared between SHA-224 and SHA-256
fn process_block(data: &[u8; 64], state: &mut [u32; 8]) {
    // Create message schedule array w[0..15]
    let mut w = [0u32; 16];

    // Load data into w[0..15] with direct indexing for better performance
    let mut i = 0;
    while i < 16 {
        w[i] = u32::from_be_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        i += 1;
    }

    // Initialize working variables to current hash value
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Process first 16 rounds with direct data access (manually unrolled)
    round_00_15!(a, b, c, d, e, f, g, h, w, 0);
    round_00_15!(a, b, c, d, e, f, g, h, w, 1);
    round_00_15!(a, b, c, d, e, f, g, h, w, 2);
    round_00_15!(a, b, c, d, e, f, g, h, w, 3);
    round_00_15!(a, b, c, d, e, f, g, h, w, 4);
    round_00_15!(a, b, c, d, e, f, g, h, w, 5);
    round_00_15!(a, b, c, d, e, f, g, h, w, 6);
    round_00_15!(a, b, c, d, e, f, g, h, w, 7);
    round_00_15!(a, b, c, d, e, f, g, h, w, 8);
    round_00_15!(a, b, c, d, e, f, g, h, w, 9);
    round_00_15!(a, b, c, d, e, f, g, h, w, 10);
    round_00_15!(a, b, c, d, e, f, g, h, w, 11);
    round_00_15!(a, b, c, d, e, f, g, h, w, 12);
    round_00_15!(a, b, c, d, e, f, g, h, w, 13);
    round_00_15!(a, b, c, d, e, f, g, h, w, 14);
    round_00_15!(a, b, c, d, e, f, g, h, w, 15);

    // Process remaining rounds (fully unrolled)
    round_16_63!(a, b, c, d, e, f, g, h, w, 16);
    round_16_63!(a, b, c, d, e, f, g, h, w, 17);
    round_16_63!(a, b, c, d, e, f, g, h, w, 18);
    round_16_63!(a, b, c, d, e, f, g, h, w, 19);
    round_16_63!(a, b, c, d, e, f, g, h, w, 20);
    round_16_63!(a, b, c, d, e, f, g, h, w, 21);
    round_16_63!(a, b, c, d, e, f, g, h, w, 22);
    round_16_63!(a, b, c, d, e, f, g, h, w, 23);
    round_16_63!(a, b, c, d, e, f, g, h, w, 24);
    round_16_63!(a, b, c, d, e, f, g, h, w, 25);
    round_16_63!(a, b, c, d, e, f, g, h, w, 26);
    round_16_63!(a, b, c, d, e, f, g, h, w, 27);
    round_16_63!(a, b, c, d, e, f, g, h, w, 28);
    round_16_63!(a, b, c, d, e, f, g, h, w, 29);
    round_16_63!(a, b, c, d, e, f, g, h, w, 30);
    round_16_63!(a, b, c, d, e, f, g, h, w, 31);
    round_16_63!(a, b, c, d, e, f, g, h, w, 32);
    round_16_63!(a, b, c, d, e, f, g, h, w, 33);
    round_16_63!(a, b, c, d, e, f, g, h, w, 34);
    round_16_63!(a, b, c, d, e, f, g, h, w, 35);
    round_16_63!(a, b, c, d, e, f, g, h, w, 36);
    round_16_63!(a, b, c, d, e, f, g, h, w, 37);
    round_16_63!(a, b, c, d, e, f, g, h, w, 38);
    round_16_63!(a, b, c, d, e, f, g, h, w, 39);
    round_16_63!(a, b, c, d, e, f, g, h, w, 40);
    round_16_63!(a, b, c, d, e, f, g, h, w, 41);
    round_16_63!(a, b, c, d, e, f, g, h, w, 42);
    round_16_63!(a, b, c, d, e, f, g, h, w, 43);
    round_16_63!(a, b, c, d, e, f, g, h, w, 44);
    round_16_63!(a, b, c, d, e, f, g, h, w, 45);
    round_16_63!(a, b, c, d, e, f, g, h, w, 46);
    round_16_63!(a, b, c, d, e, f, g, h, w, 47);
    round_16_63!(a, b, c, d, e, f, g, h, w, 48);
    round_16_63!(a, b, c, d, e, f, g, h, w, 49);
    round_16_63!(a, b, c, d, e, f, g, h, w, 50);
    round_16_63!(a, b, c, d, e, f, g, h, w, 51);
    round_16_63!(a, b, c, d, e, f, g, h, w, 52);
    round_16_63!(a, b, c, d, e, f, g, h, w, 53);
    round_16_63!(a, b, c, d, e, f, g, h, w, 54);
    round_16_63!(a, b, c, d, e, f, g, h, w, 55);
    round_16_63!(a, b, c, d, e, f, g, h, w, 56);
    round_16_63!(a, b, c, d, e, f, g, h, w, 57);
    round_16_63!(a, b, c, d, e, f, g, h, w, 58);
    round_16_63!(a, b, c, d, e, f, g, h, w, 59);
    round_16_63!(a, b, c, d, e, f, g, h, w, 60);
    round_16_63!(a, b, c, d, e, f, g, h, w, 61);
    round_16_63!(a, b, c, d, e, f, g, h, w, 62);
    round_16_63!(a, b, c, d, e, f, g, h, w, 63);

    // Add the compressed chunk to the current hash value
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use crate::ffi::sha2_ffi::{SHA224_CTX, SHA256_CTX};

    use super::*;
    use alloc::vec;

    #[test]
    fn test_sha256_standard_vectors() {
        // Combine all standard test vectors into a single table-driven test
        let empty_data: &[u8] = &[];
        let hello_world_data: &[u8] = b"hello world";
        let abc_data: &[u8] = b"abc";
        let abcd_data: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let abcdef_data: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

        let test_vectors = [
            (
                empty_data,
                [
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                    0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                    0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ],
            ),
            (
                hello_world_data,
                [
                    0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda,
                    0x7d, 0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88,
                    0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
                ],
            ),
            (
                abc_data,
                [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ],
            ),
            (
                abcd_data,
                [
                    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c,
                    0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec,
                    0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
                ],
            ),
            (
                abcdef_data,
                [
                    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b,
                    0x04, 0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac,
                    0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1,
                ],
            ),
        ];

        // Test each vector with both one-shot and incremental hashing
        for (input, expected) in &test_vectors {
            // Test one-shot hashing
            let mut result = [0u8; SHA256_DIGEST_LEN];
            sha256_digest(input, &mut result);
            assert_eq!(result, *expected);

            // Test incremental hashing (single update)
            let mut context = SHA256_CTX::default();
            context.update(input);
            let mut result = [0u8; SHA256_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);

            test_sha256_incremental_patterns(input, expected);
        }
    }

    // Helper function to test various incremental hashing patterns for SHA-256
    fn test_sha256_incremental_patterns(data: &[u8], expected: &[u8; SHA256_DIGEST_LEN]) {
        // Test 1: Simple two-part split
        if data.len() > 1 {
            let split_point = data.len() / 2;
            let mut context = SHA256_CTX::default();
            context.update(&data[..split_point]);
            context.update(&data[split_point..]);
            let mut result = [0u8; SHA256_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 2: Every possible chunk size
        for chunk_size in 1..=data.len() {
            let mut context = SHA256_CTX::default();
            for chunk in data.chunks(chunk_size) {
                context.update(chunk);
            }
            let mut result = [0u8; SHA256_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 3: Alternating single byte and multi-byte updates
        if data.len() >= 16 {
            let mut context = SHA256_CTX::default();
            context.update(&data[0..1]); // 1 byte
            context.update(&data[1..5]); // 4 bytes
            context.update(&data[5..6]); // 1 byte
            context.update(&data[6..15]); // 9 bytes
            context.update(&data[15..16]); // 1 byte
            context.update(&data[16..]); // remaining bytes
            let mut result = [0u8; SHA256_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 4: Empty updates before, after, and between
        let empty_data: &[u8] = &[];
        let mut context = SHA256_CTX::default();
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
        let mut result = [0u8; SHA256_DIGEST_LEN];
        context.finalize(&mut result);
        assert_eq!(result, *expected);
    }

    #[test]
    fn test_sha224_standard_vectors() {
        // Standard test vectors for SHA-224
        let empty_data: &[u8] = &[];
        let abc_data: &[u8] = b"abc";
        let abcd_data: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let abcdef_data: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

        let test_vectors = [
            (
                empty_data,
                [
                    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28,
                    0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3,
                    0xe4, 0x2f,
                ],
            ),
            (
                abc_data,
                [
                    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd,
                    0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c,
                    0x9d, 0xa7,
                ],
            ),
            (
                abcd_data,
                [
                    0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd,
                    0x89, 0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52,
                    0x25, 0x25,
                ],
            ),
            (
                abcdef_data,
                [
                    0xc9, 0x7c, 0xa9, 0xa5, 0x59, 0x85, 0x0c, 0xe9, 0x7a, 0x04, 0xa9, 0x6d, 0xef,
                    0x6d, 0x99, 0xa9, 0xe0, 0xe0, 0xe2, 0xab, 0x14, 0xe6, 0xb8, 0xdf, 0x26, 0x5f,
                    0xc0, 0xb3,
                ],
            ),
        ];

        // Test each vector with both one-shot and incremental hashing
        for (input, expected) in &test_vectors {
            // Test one-shot hashing
            let mut result = [0u8; SHA224_DIGEST_LEN];
            sha224_digest(input, &mut result);
            assert_eq!(result, *expected);

            // Test incremental hashing (single update)
            let mut context = SHA224_CTX::default();
            context.update(input);
            let mut result: [u8; 28] = [0u8; SHA224_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);

            test_sha224_incremental_patterns(input, expected);
        }
    }

    // Helper function to test various incremental hashing patterns for SHA-224
    fn test_sha224_incremental_patterns(data: &[u8], expected: &[u8; SHA224_DIGEST_LEN]) {
        // Test 1: Simple two-part split
        if data.len() > 1 {
            let split_point = data.len() / 2;
            let mut context = SHA224_CTX::default();
            context.update(&data[..split_point]);
            context.update(&data[split_point..]);
            let mut result = [0u8; SHA224_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 2: Every possible chunk size
        for chunk_size in 1..=data.len() {
            let mut context = SHA224_CTX::default();
            for chunk in data.chunks(chunk_size) {
                context.update(chunk);
            }
            let mut result = [0u8; SHA224_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 3: Alternating single byte and multi-byte updates
        if data.len() >= 16 {
            let mut context = SHA224_CTX::default();
            context.update(&data[0..1]); // 1 byte
            context.update(&data[1..5]); // 4 bytes
            context.update(&data[5..6]); // 1 byte
            context.update(&data[6..15]); // 9 bytes
            context.update(&data[15..16]); // 1 byte
            context.update(&data[16..]); // remaining bytes
            let mut result = [0u8; SHA224_DIGEST_LEN];
            context.finalize(&mut result);
            assert_eq!(result, *expected);
        }

        // Test 4: Empty updates before, after, and between
        let empty_data: &[u8] = &[];
        let mut context = SHA224_CTX::default();
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
        let mut result = [0u8; SHA224_DIGEST_LEN];
        context.finalize(&mut result);
        assert_eq!(result, *expected);
    }

    #[test]
    fn test_sha256_million_a() {
        // Test with a million 'a' characters
        // This is a standard test vector for SHA-256
        // Expected hash: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
        let expected = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];

        // Create a context and update it with a million 'a' characters
        let mut context = SHA256_CTX::default();
        let chunk = [b'a'; 1000]; // 1000 'a' characters
        for _ in 0..1000 {
            // 1000 * 1000 = 1,000,000
            context.update(&chunk);
        }
        let mut result = [0u8; SHA256_DIGEST_LEN];
        context.finalize(&mut result);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha224_million_a() {
        // Test with a million 'a' characters
        // This is a standard test vector for SHA-224
        // Expected hash: 20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67
        let expected = [
            0x20, 0x79, 0x46, 0x55, 0x98, 0x0c, 0x91, 0xd8, 0xbb, 0xb4, 0xc1, 0xea, 0x97, 0x61,
            0x8a, 0x4b, 0xf0, 0x3f, 0x42, 0x58, 0x19, 0x48, 0xb2, 0xee, 0x4e, 0xe7, 0xad, 0x67,
        ];

        // Create a context and update it with a million 'a' characters
        let mut context = SHA224_CTX::default();
        let chunk = [b'a'; 1000]; // 1000 'a' characters
        for _ in 0..1000 {
            // 1000 * 1000 = 1,000,000
            context.update(&chunk);
        }
        let mut result = [0u8; SHA224_DIGEST_LEN];
        context.finalize(&mut result);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_context_reset() {
        // Test SHA-256 reset
        let data1 = b"hello";
        let data2 = b"world";

        // First hash
        let mut context = SHA256_CTX::default();
        context.update(data1);

        // Reset and hash different data
        context.init();
        context.update(data2);
        let mut result = [0u8; SHA256_DIGEST_LEN];
        context.finalize(&mut result);

        // Compare with direct hash of second data
        let mut expected = [0u8; SHA256_DIGEST_LEN];
        sha256_digest(data2, &mut expected);
        assert_eq!(result, expected);

        // Test SHA-224 reset
        let mut context = SHA224_CTX::default();
        context.update(data1);

        // Reset and hash different data
        context.init();
        context.update(data2);
        let mut result = [0u8; SHA224_DIGEST_LEN];
        context.finalize(&mut result);

        // Compare with direct hash of second data
        let mut expected = [0u8; SHA224_DIGEST_LEN];
        sha224_digest(data2, &mut expected);
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

            // Test SHA-256
            // Test direct hashing
            let mut direct_result = [0u8; SHA256_DIGEST_LEN];
            sha256_digest(&data, &mut direct_result);

            // Test incremental hashing
            let mut context = SHA256_CTX::default();
            context.update(&data);
            let mut incremental_result = [0u8; SHA256_DIGEST_LEN];
            context.finalize(&mut incremental_result);

            assert_eq!(direct_result, incremental_result);

            // Test SHA-224
            // Test direct hashing
            let mut direct_result = [0u8; SHA224_DIGEST_LEN];
            sha224_digest(&data, &mut direct_result);

            // Test incremental hashing
            let mut context = SHA224_CTX::default();
            context.update(&data);
            let mut incremental_result = [0u8; SHA224_DIGEST_LEN];
            context.finalize(&mut incremental_result);

            assert_eq!(direct_result, incremental_result);
        }
    }
}
