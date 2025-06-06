//! SHA-256 hash function implementation

/// The size of a SHA-256 digest in bytes (32 bytes = 256 bits)
pub const DIGEST_LEN: usize = 32;

/// The internal block size of SHA-256 in bytes (64 bytes = 512 bits)
pub const BLOCK_LEN: usize = 64;

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

/// SHA-256 hash function context
pub struct Context {
    /// Current hash state (h0-h7 in the pseudocode)
    state: [u32; 8],

    /// Unprocessed data buffer
    buffer: [u8; BLOCK_LEN],

    /// Number of bytes in the buffer
    buffer_len: usize,

    /// Total number of bits processed
    total_bits: u64,
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
            state: H_INIT,
            buffer: [0; BLOCK_LEN],
            buffer_len: 0,
            total_bits: 0,
        }
    }

    /// Updates the hash state with input data
    pub fn update(&mut self, data: &[u8]) {
        // Update the total bit count
        self.total_bits += (data.len() as u64) * 8;

        // Process the input data
        let mut data_index = 0;

        // If we have data in the buffer, try to fill it first
        if self.buffer_len > 0 {
            while data_index < data.len() && self.buffer_len < BLOCK_LEN {
                self.buffer[self.buffer_len] = data[data_index];
                self.buffer_len += 1;
                data_index += 1;
            }

            // If the buffer is full, process it
            if self.buffer_len == BLOCK_LEN {
                self.transform();
                self.buffer_len = 0;
            }
        }

        // Process as many complete blocks as possible
        while data_index + BLOCK_LEN <= data.len() {
            self.buffer
                .copy_from_slice(&data[data_index..(data_index + BLOCK_LEN)]);
            self.transform();
            data_index += BLOCK_LEN;
        }

        // Store any remaining bytes in the buffer
        while data_index < data.len() {
            self.buffer[self.buffer_len] = data[data_index];
            self.buffer_len += 1;
            data_index += 1;
        }
    }

    /// Finalizes the hash computation and returns the digest
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        // Pad the message
        // 1. Append a single '1' bit
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // 2. Append '0' bits until the message length is congruent to 448 modulo 512
        if self.buffer_len > BLOCK_LEN - 8 {
            // Not enough room for the length, pad with zeros and process this block
            while self.buffer_len < BLOCK_LEN {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.transform();
            self.buffer_len = 0;
        }

        // Pad with zeros up to the point where the length will be added
        while self.buffer_len < BLOCK_LEN - 8 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // 3. Append the length as a 64-bit big-endian integer
        let bit_len = self.total_bits;
        self.buffer[self.buffer_len] = ((bit_len >> 56) & 0xff) as u8;
        self.buffer[self.buffer_len + 1] = ((bit_len >> 48) & 0xff) as u8;
        self.buffer[self.buffer_len + 2] = ((bit_len >> 40) & 0xff) as u8;
        self.buffer[self.buffer_len + 3] = ((bit_len >> 32) & 0xff) as u8;
        self.buffer[self.buffer_len + 4] = ((bit_len >> 24) & 0xff) as u8;
        self.buffer[self.buffer_len + 5] = ((bit_len >> 16) & 0xff) as u8;
        self.buffer[self.buffer_len + 6] = ((bit_len >> 8) & 0xff) as u8;
        self.buffer[self.buffer_len + 7] = (bit_len & 0xff) as u8;

        // Process the final block
        self.transform();

        // Convert state to bytes in big-endian format
        let mut digest = [0u8; DIGEST_LEN];
        for i in 0..8 {
            digest[i * 4] = (self.state[i] >> 24) as u8;
            digest[i * 4 + 1] = (self.state[i] >> 16) as u8;
            digest[i * 4 + 2] = (self.state[i] >> 8) as u8;
            digest[i * 4 + 3] = self.state[i] as u8;
        }

        digest
    }

    /// Resets the context to its initial state
    pub fn reset(&mut self) {
        self.state = H_INIT;
        self.buffer = [0; BLOCK_LEN];
        self.buffer_len = 0;
        self.total_bits = 0;
    }

    /// Internal function to process a complete 64-byte block
    fn transform(&mut self) {
        // Create message schedule array w[0..63]
        let mut w = [0u32; 64];

        // Copy block into first 16 words w[0..15] of the message schedule array
        // Convert from bytes to words (big-endian)
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = ((self.buffer[i * 4] as u32) << 24)
                | ((self.buffer[i * 4 + 1] as u32) << 16)
                | ((self.buffer[i * 4 + 2] as u32) << 8)
                | (self.buffer[i * 4 + 3] as u32);
        }

        // Extend the first 16 words into the remaining 48 words w[16..63]
        for i in 16..64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables to current hash value
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Compression function main loop
        for i in 0..64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

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
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Computes the SHA-256 digest of the input data in one step
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut context = Context::new();
    context.update(data);
    context.finalize()
}

/// Right rotate a 32-bit value by the specified number of bits
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        // SHA-256 hash of empty string
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];

        let result = digest(&[]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hello_world() {
        // SHA-256 hash of "hello world"
        // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        let result = digest(b"hello world");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_abc() {
        // SHA-256 hash of "abc"
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let result = digest(b"abc");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_incremental_hashing() {
        let expected = digest(b"hello world");

        let mut context = Context::new();
        context.update(b"hello ");
        context.update(b"world");
        let result = context.finalize();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_long_input() {
        // Test with a known test vector that spans multiple blocks
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

        // Known SHA-256 hash of the input
        // cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1
        let expected = [
            0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04,
            0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03,
            0x7a, 0xfe, 0xe9, 0xd1,
        ];

        // Compute hash incrementally
        let mut context = Context::new();
        for chunk in input.chunks(20) {
            // Process in smaller chunks to test incremental hashing
            context.update(chunk);
        }
        let result = context.finalize();

        assert_eq!(result, expected);

        // Also test the one-shot function
        let one_shot_result = digest(input);
        assert_eq!(one_shot_result, expected);
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
        let mut context = Context::new();
        let chunk = [b'a'; 1000]; // 1000 'a' characters
        for _ in 0..1000 {
            // 1000 * 1000 = 1,000,000
            context.update(&chunk);
        }
        let result = context.finalize();

        assert_eq!(result, expected);
    }
}
