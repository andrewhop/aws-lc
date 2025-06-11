// SHA-256 hash function implementation.
//
// This is a no_std, no_alloc implementation with no external dependencies,
// suitable for use in constrained environments including FIPS-validated modules.
//
// # Examples
//
// ```
// use keep::hash::sha256;
//
// // One-shot hashing
// let data = b"hello world";
// let mut hash = [0u8; sha256::DIGEST_LEN];
// sha256::digest(data, &mut hash);
//
// // Incremental hashing
// let mut context = sha256::Context::new();
// context.update(b"hello ");
// context.update(b"world");
// let mut hash = [0u8; sha256::DIGEST_LEN];
// context.finalize(&mut hash);
// ```

#[cfg(test)]
extern crate alloc;

/// The size of a SHA-256 digest in bytes (32 bytes = 256 bits)
pub const DIGEST_LEN: usize = 32;

/// The internal block size of SHA-256 in bytes (64 bytes = 512 bits)
pub const BLOCK_LEN: usize = 64;

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

/// Initial hash values: first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// / SHA-256 hash function context
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
    /// Creates a new SHA-256 context with the default initial state
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
        // Update the total bit count
        let bits = (data.len() as u64) * 8;
        let new_nl = self.Nl.wrapping_add((bits & 0xFFFF_FFFF) as u32);

        // Check for overflow
        if new_nl < self.Nl {
            self.Nh = self.Nh.wrapping_add(1); // Carry to high word
        }
        self.Nl = new_nl;

        // Add high bits
        self.Nh = self.Nh.wrapping_add((bits >> 32) as u32);

        // Process the input data
        let mut data_index = 0;

        // If we have data in the buffer, try to fill it first
        if self.num > 0 {
            // Calculate how many bytes we can copy to fill the buffer
            let bytes_to_copy = core::cmp::min(BLOCK_LEN - self.num as usize, data.len());

            // Copy bytes to the buffer
            self.data[self.num as usize..self.num as usize + bytes_to_copy]
                .copy_from_slice(&data[..bytes_to_copy]);

            self.num += bytes_to_copy as u32;
            data_index = bytes_to_copy;

            // If the buffer is full, process it
            if self.num as usize == BLOCK_LEN {
                self.transform();
                self.num = 0;
            }
        }

        // Process as many complete blocks as possible
        while data_index + BLOCK_LEN <= data.len() {
            self.data
                .copy_from_slice(&data[data_index..data_index + BLOCK_LEN]);
            self.transform();
            data_index += BLOCK_LEN;
        }

        // Store any remaining bytes in the buffer
        if data_index < data.len() {
            let remaining = data.len() - data_index;
            self.data[self.num as usize..self.num as usize + remaining]
                .copy_from_slice(&data[data_index..]);
            self.num += remaining as u32;
        }
    }

    /// Finalizes the hash computation and returns the digest
    #[unsafe(link_section = "__TEXT,__fips_b")]
    pub fn finalize(mut self, output: &mut [u8]) {
        // assert!(output.len() >= DIGEST_LEN);
        // Pad the message
        // 1. Append a single '1' bit
        self.data[self.num as usize] = PADDING_BYTE;
        self.num += 1;

        // 2. Append '0' bits until the message length is congruent to 448 modulo 512
        if (self.num as usize) > BLOCK_LEN - 8 {
            // Not enough room for the length, pad with zeros and process this block
            while (self.num as usize) < BLOCK_LEN {
                self.data[self.num as usize] = PADDING_ZERO;
                self.num += 1;
            }
            self.transform();
            self.num = 0;
        }

        // Pad with zeros up to the point where the length will be added
        while (self.num as usize) < BLOCK_LEN - 8 {
            self.data[self.num as usize] = PADDING_ZERO;
            self.num += 1;
        }

        // 3. Append the length as a 64-bit big-endian integer
        let bit_len_bytes = [
            (self.Nh >> 24) as u8,
            (self.Nh >> 16) as u8,
            (self.Nh >> 8) as u8,
            self.Nh as u8,
            (self.Nl >> 24) as u8,
            (self.Nl >> 16) as u8,
            (self.Nl >> 8) as u8,
            self.Nl as u8,
        ];
        self.data[self.num as usize..self.num as usize + 8].copy_from_slice(&bit_len_bytes);

        // Process the final block
        self.transform();

        // Convert state to bytes in big-endian format
        for i in 0..8 {
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

    /// Internal function to process a complete 64-byte block
    fn transform(&mut self) {
        // Create message schedule array w[0..63]
        let mut w = [0u32; 64];

        // Copy block into first 16 words w[0..15] of the message schedule array
        // Convert from bytes to words (big-endian)
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let bytes = [
                self.data[i * 4],
                self.data[i * 4 + 1],
                self.data[i * 4 + 2],
                self.data[i * 4 + 3],
            ];
            *word = u32::from_be_bytes(bytes);
        }

        // Extend the first 16 words into the remaining 48 words w[16..63]
        for i in 16..64 {
            let s0 = small_sigma0(w[i - 15]);
            let s1 = small_sigma1(w[i - 2]);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables to current hash value
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // Compression function main loop
        for i in 0..64 {
            let s1 = sigma1(e);
            let ch_result = ch(e, f, g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch_result)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = sigma0(a);
            let maj_result = maj(a, b, c);
            let temp2 = s0.wrapping_add(maj_result);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

/// Computes the SHA-256 digest of the input data in one step
#[unsafe(link_section = "__TEXT,__fips_b")]
pub fn digest(data: &[u8], output: &mut [u8]) {
    let mut context = Context::new();
    context.update(data);
    context.finalize(output);
}

/// Right rotate a 32-bit value by the specified number of bits
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Choose function: (x & y) ^ (!x & z)
/// If x then y else z
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Majority function: (x & y) ^ (x & z) ^ (y & z)
/// Returns the bit value that appears most often in x, y, z
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Sigma0 function: rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
/// Used in the compression function for working variables
#[inline]
fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Sigma1 function: rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
/// Used in the compression function for working variables
#[inline]
fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Small sigma0 function: rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
/// Used in message schedule array preparation
#[inline]
fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Small sigma1 function: rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
/// Used in message schedule array preparation
#[inline]
fn small_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}
