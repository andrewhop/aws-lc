# Rust Castle

Rust Castle is a Rust component built into AWS-LC libcrypto, consisting of three distinct crates:

## Components

### Keep

Keep is a `no_std`, no allocation library for FIPS algorithm primitives. It can have no external dependencies or function calls outside itself. Keep will eventually be its own standalone FIPS module with its own integrity check.

Example API (SHA-256):

```rust
// One-shot hashing
let data = b"hello world";
let mut hash = [0u8; sha256::DIGEST_LEN];
sha256::digest(data, &mut hash);

// Incremental hashing
let mut context = sha256::Context::new();
context.update(b"hello ");
context.update(b"world");
let mut hash = [0u8; sha256::DIGEST_LEN];
context.finalize(&mut hash);
```

### Bailey

Bailey contains cryptographic Rust utility functions. It can call functions inside Keep, other functions in Bailey, or the Rust standard library.

### Drawbridge

Drawbridge is a Rust to C FFI layer. It can call functions in Bailey or Keep and should be as simple as possible to translate between C and Rust, containing no interesting logic.

Example API (SHA-256 FFI):

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256_Init(sha: *mut SHA256_CTX) -> i32 {
    if sha.is_null() {
        return 0;
    }
    let sha = unsafe { &mut *sha };
    sha.reset();
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256_Update(
    sha: *mut SHA256_CTX,
    data: *const core::ffi::c_void,
    len: usize,
) -> i32 {
    // Implementation details...
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256_Final(out: *mut u8, sha: *mut SHA256_CTX) -> i32 {
    // Implementation details...
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA256(data: *const u8, len: usize, out: *mut u8) -> *mut u8 {
    // Implementation details...
}
```

## AWS-LC C Code Integration

AWS-LC C code in libcrypto interacts with Drawbridge through the standard OpenSSL-compatible headers like `sha.h`. The C code calls functions like `SHA256_Init`, `SHA256_Update`, and `SHA256_Final` which are implemented in Drawbridge:

```c
// C code using the SHA-256 functions
SHA256_CTX ctx;
SHA256_Init(&ctx);
SHA256_Update(&ctx, data, data_len);
SHA256_Final(digest, &ctx);

// Or the one-shot function
SHA256(data, data_len, digest);
```

## Future Integration with aws-lc-rs

aws-lc-rs is a separate crate that provides idiomatic Rust bindings for AWS-LC, implementing the Ring API. Currently, aws-lc-rs interacts with AWS-LC through the C layer.

In the future, aws-lc-rs will be able to call functions in Keep and Bailey directly, bypassing the C layer. This will provide full Rust memory safety guarantees and improve performance by eliminating the FFI overhead.

## Architecture Diagram

### Past Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      aws-lc-rs                          │
│               (Idiomatic Rust API - Ring)               │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                     AWS-LC (C code)                     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              C API (sha.h, etc.)                │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Near Future Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      aws-lc-rs                          │
│               (Idiomatic Rust API - Ring)               │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                     AWS-LC (C code)                     │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              C API (sha.h, etc.)                │    │
└──┼─────────────────────────────────────────────────┼────┘
   │                                                 │
┌──┼─────────────────────────────────────────────────┼────┐
│  │                 Drawbridge                      │    │
│  │         (Rust to C FFI Translation)             │    │
│  └─────────────────────────────────────────────────┘    │
│                        │                                │
│  ┌─────────────────────┴─────────────────────────────┐  │
│  │                    Bailey                         │  │
│  │         (Cryptographic Utility Functions)         │  │
│  └─────────────────────┬─────────────────────────────┘  │
│                        │                                │
│  ┌─────────────────────┴─────────────────────────────┐  │
│  │                     Keep                          │  │
│  │      (FIPS Algorithm Primitives - no_std)         │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                         │
│                    rust_castle                          │
└─────────────────────────────────────────────────────────┘
```

### Far Future Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      aws-lc-rs                          │
│               (Idiomatic Rust API - Ring)               │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────┐    │
│  │                    Bailey                       │    │
│  └─────────────────────┬───────────────────────────┘    │
│                        │                                │
│  ┌─────────────────────┴───────────────────────────┐    │
│  │                     Keep                        │    │
│  └─────────────────────────────────────────────────┘    │
│                    rust_castle                          │
└─────────────────────────────────────────────────────────┘
```
