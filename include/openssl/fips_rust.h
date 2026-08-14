#ifndef OPENSSL_HEADER_FIPS_RUST_H
#define OPENSSL_HEADER_FIPS_RUST_H

#include <openssl/base.h>


#if defined(__cplusplus)
extern "C" {
#endif

// AWS_LC_FIPS_get_digest writes the SHA-256 digest of the native-Rust FIPS
// module's code region into |out|. |out_len| must be at least 32. Returns 1 on
// success, 0 on failure (null pointer or insufficient buffer).
OPENSSL_EXPORT int AWS_LC_FIPS_get_digest(uint8_t* out, size_t out_len);

// AWS_LC_FIPS_check_integrity verifies that the native-Rust FIPS module's
// critical functions lie within its code boundary. Returns 1 if the check
// passes, 0 otherwise.
OPENSSL_EXPORT int AWS_LC_FIPS_check_integrity(void);

#if defined(__cplusplus)
}  // extern C

#endif


#endif  // OPENSSL_HEADER_FIPS_RUST_H
