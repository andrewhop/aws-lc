#ifndef OPENSSL_HEADER_CASTLE_H
#define OPENSSL_HEADER_CASTLE_H

#include <openssl/base.h>


#if defined(__cplusplus)
extern "C" {
#endif

OPENSSL_EXPORT int AWS_LC_FIPS_get_digest(uint8_t* out, size_t out_len);
OPENSSL_EXPORT size_t AWS_LC_FIPS_check_integrity();

#if defined(__cplusplus)
}  // extern C

#endif


#endif  // OPENSSL_HEADER_CASTLE_H
