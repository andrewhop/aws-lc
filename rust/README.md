# Native-Rust FIPS module for AWS-LC

This directory holds a Cargo workspace that implements part of AWS-LC's
cryptography in native Rust and links it into `libcrypto` behind the existing C
API. C consumers (such as s2n-tls) and Rust consumers (such as aws-lc-rs) call
the same OpenSSL-compatible functions; the implementation underneath is Rust.

Today the workspace provides the SHA-1, SHA-224, and SHA-256 implementations plus
a FIPS integrity self-check.

## Workspace layout

The workspace has two crates:

- **`fips_core`** — the FIPS boundary. It contains the cryptographic primitives
  (`src/digest/`), the C ABI shim (`src/ffi/`), and the integrity check
  (`src/integrity/`). It is written in no_std, no-allocation style with no
  external dependencies. It builds as a `staticlib` (`libfips_core.a`).
- **`fips_module`** — packaging. Its build script (`build.rs`) assembles the FIPS
  integrity boundary around `fips_core`'s code and produces the final static
  archive (`libfips_module.a`) that CMake links into `libcrypto`. It also exports
  `AWS_LC_FIPS_module_version`.

Within `fips_core`:

- `digest/` — SHA-1 and SHA-2 implementations behind a small `Digest` trait
  (`init` / `update` / `finalize`).
- `ffi/` — thin `extern "C"` wrappers exposing the OpenSSL-compatible symbols
  (`SHA256_Init`, `SHA256_Update`, `SHA256_Final`, `SHA256`, and so on). These do
  null checks and pointer/slice conversion only; they contain no crypto logic.
- `integrity/` — the code-boundary self-check (see below).

## Example API

The Rust API, using SHA-256:

```rust
use fips_core::digest::Digest;
use fips_core::digest::sha2::{self, SHA256, SHA256_DIGEST_LEN};

// Incremental hashing via the Digest trait.
let mut ctx = SHA256::default();
ctx.update(b"hello ");
ctx.update(b"world");
let mut hash = [0u8; SHA256_DIGEST_LEN];
ctx.finalize(&mut hash);

// One-shot hashing.
let mut hash = [0u8; SHA256_DIGEST_LEN];
sha2::sha256_digest(b"hello world", &mut hash);
```

The C ABI shim in `ffi/` exposes the same operations to C:

```c
SHA256_CTX ctx;
SHA256_Init(&ctx);
SHA256_Update(&ctx, data, data_len);
SHA256_Final(digest, &ctx);

// Or the one-shot function.
SHA256(data, data_len, digest);
```

## Building

CMake drives the build. When `AWSLC_RUST_FIPS` is enabled (the default), the
top-level build runs `cargo build` in this directory and links `libfips_module.a`
into `libcrypto`. A Rust/Cargo toolchain is required in that configuration. To
build the crates directly:

```sh
cd rust
cargo build        # or: cargo build --release
cargo test
```

## FIPS integrity boundary

FIPS 140-3 requires verifying the integrity of the code inside the module
boundary. `fips_core/src/integrity/mod.rs` checks that every critical function
lies within a contiguous code region delimited by two marker symbols
(`AWS_LC_fips_text_start` / `AWS_LC_fips_text_end`), and computes a SHA-256 digest
over that region.

Because the Rust toolchain offers no stable control over code placement or symbol
ordering, `fips_module/build.rs` establishes the region by relinking object files
in a fixed order (`start | fips_core | end`) with `ld -r`. This relies on a
Unix-style binutils toolchain and is why `fips_core` ships as a `staticlib`. For
the full explanation — and the compiler features that would remove this
workaround and enable a pure-Rust AWS-LC that pure-Rust applications can depend on
directly — see [FIPS_INTEGRITY.md](FIPS_INTEGRITY.md).

## Architecture: past, present, future

**Past — C only.** All customers called C implementations in `libcrypto`.

```
 s2n-tls (C)      aws-lc-rs (Rust)
      \               /
       v             v
     C implementations in libcrypto
```

**Present — Rust behind the C API.** The SHA implementations are Rust, linked
into `libcrypto` and reached through the existing C API. Customers are unchanged.

```
 s2n-tls (C)      aws-lc-rs (Rust)
      \               /
       v             v
        C ABI shim (fips_core::ffi)
                 |
                 v
     fips_core primitives (Rust)   [in libcrypto]
```

**Future — native Rust path.** A pure-Rust build of `fips_core` is consumed
directly by Rust callers, while C callers continue through the C API. Reaching
this depends on the toolchain features in [FIPS_INTEGRITY.md](FIPS_INTEGRITY.md).

```
 s2n-tls (C)                    aws-lc-rs (Rust)
      \                               /
       v                             v
   C ABI shim                  direct Rust calls
       \                             /
        v                           v
            fips_core primitives (Rust)
```
