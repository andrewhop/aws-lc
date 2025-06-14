//! Common utilities for SHA-2 family algorithms (SHA-224 and SHA-256).

/// Common update function for SHA-224 and SHA-256
pub fn update_hash_state(
    data: &[u8],
    h: &mut [u32; 8],
    buffer: &mut [u8; 64],
    num: &mut u32,
    nl: &mut u32,
    nh: &mut u32,
) {
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
        buffer[*num as usize..*num as usize + remaining]
            .copy_from_slice(&data[data_index..]);
        *num += remaining as u32;
    }
}

/// Padding byte (binary 10000000)
pub const PADDING_BYTE: u8 = 0x80;

/// Padding zero byte
pub const PADDING_ZERO: u8 = 0x00;

/// Round constants K[0..63]
/// First 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
pub const K: [u32; 64] = [
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
pub const fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Choose function: (x & y) ^ (!x & z)
/// If x then y else z
#[inline(always)]
pub const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Majority function: (x & y) ^ (x & z) ^ (y & z)
/// Returns the bit value that appears most often in x, y, z
#[inline(always)]
pub const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Sigma0 function: rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
/// Used in the compression function for working variables
#[inline(always)]
pub const fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Sigma1 function: rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
/// Used in the compression function for working variables
#[inline(always)]
pub const fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Small sigma0 function: rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
/// Used in message schedule array preparation
#[inline(always)]
pub const fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Small sigma1 function: rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
/// Used in message schedule array preparation
#[inline(always)]
pub const fn small_sigma1(x: u32) -> u32 {
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
pub fn process_block(data: &[u8; 64], state: &mut [u32; 8]) {
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
