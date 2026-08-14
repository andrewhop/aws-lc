# FIPS integrity boundary: how it is built and what would simplify it

FIPS 140-3 requires an approved integrity technique applied to all code within
the cryptographic module boundary. In practice this means: define a contiguous
region of machine code, and verify at runtime that the code matches a known-good
value (a digest or HMAC computed over the region).

This document explains how the native-Rust FIPS module establishes that boundary
today, why the approach is what it is, and which Rust toolchain features would let
us replace the current workaround — in particular so a pure-Rust application could
depend on a pure-Rust AWS-LC directly.

## How the boundary is built today

The mechanism lives in `fips_module/build.rs` and `fips_core/src/integrity/mod.rs`:

1. Two marker functions, `AWS_LC_fips_text_start` and `AWS_LC_fips_text_end`
   (`fips_module/markers/{start,end}.rs`), are compiled *as separate staticlib
   crates* so each lands in its own object file.
2. `build.rs` extracts the object files from `libfips_core.a` (the crypto code)
   and the two marker archives with `ar x`.
3. It locates the objects defining the boundary symbols and the module entry
   symbol with `nm`.
4. It concatenates them with `ld -r` in a fixed order — `start | fips_core | end`
   — producing one relocatable object whose `.text` runs contiguously from
   `AWS_LC_fips_text_start` to `AWS_LC_fips_text_end`.
5. That object is re-wrapped as a static archive and linked into libcrypto.

At runtime, `verify_fips_integrity` reads the two marker addresses and checks that
every critical function lies within `[start, end)`; `get_fips_digest` hashes the
bytes of that region with SHA-256.

## Why it looks like this

AWS-LC's C FIPS module solves the same problem with first-class toolchain support,
which the Rust flow lacks:

| Concern | C approach | Rust today |
| --- | --- | --- |
| Boundary symbols | `BORINGSSL_bcm_text_start/end` via a linker script (`fips_shared.lds`) or ordered sections (`fips_shared_library_marker.c`, `.fipstx$a`/`$z`) | Marker functions relinked in order with `ld -r` |
| Contiguous, data-free region | `delocate.go` rewrites assembly so all cross-references are PC-relative and no data lands in `.text` | LTO + single codegen unit, then manual object concatenation |
| Known-good digest | `inject_hash.go` computes the digest post-link and patches it over a placeholder | Not yet implemented (digest is computed but not compared) |

The Rust workaround is a hand-rolled re-implementation of that machinery. It only
works because `fips_core` is built as a `staticlib`: only loose relocatable objects
can be extracted with `ar` and reordered with `ld -r`. A normally compiled rlib or
dylib has its layout fixed and internal symbols potentially stripped, so the
region can no longer be reordered or reliably demarcated.

## What the Rust toolchain would need

To build the boundary natively — through a normal `cargo build`, in any artifact
type, with no `ar`/`nm`/`ld -r` surgery — the toolchain would need:

1. **Stable per-function section placement.** A supported attribute to emit a
   function into a named section (today `#[link_section]` is unstable for
   functions and does not guarantee placement), so all FIPS code lands in one
   dedicated section such as `.fips_text`.
2. **Ordering guarantees within a section**, or ordering-key symbols like C's
   `$a`/`$z`, so the start/end markers reliably bracket the region without a
   manual relink.
3. **Linker-script / boundary-symbol integration from cargo** — a supported way
   to define `__start_fips_text` / `__stop_fips_text` boundary symbols around the
   region so it is contiguous in any final artifact: rlib, staticlib, dylib, or
   the consuming application binary.
4. **A "demarcate a contiguous, data-free code region" primitive** — the Rust
   equivalent of delocate's PC-relative rewrite plus `.text`-only guarantee, so
   the region is safe to hash.
5. **A post-link hash compute/embed hook** in cargo/rustc — reserve a symbol, hash
   the region after link, and patch the value in — the native equivalent of
   `inject_hash.go`. This would let the integrity check compare against a
   known-good digest instead of only checking function addresses.

A related, smaller gap surfaced while cleaning up the crate: compiling `fips_core`
as `#![no_std]` on stable Rust requires `panic = "abort"`, which in turn requires
rebuilding `core` with `-Zbuild-std` on nightly (precompiled `core` is
unwind-based). Until that is available on stable, the crate is written in no_std
style but not compiled with the attribute.

## Why this blocks a pure-Rust AWS-LC

Because none of the above exist, `fips_core` must ship as a `staticlib` and be
relinked with binutils. A pure-Rust application therefore cannot add a pure-Rust
AWS-LC as an ordinary `cargo` dependency: there is no `rlib` to depend on, no way
to preserve the code ordering the integrity check needs, and no in-crate way to
demarcate or hash the boundary. Closing the gaps above is the prerequisite for
that future.
