// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include "../fipsmodule/evp/internal.h"
#include "../kem/internal.h"
#include "../internal.h"
#include "internal.h"

static void hmac_key_free(EVP_PKEY *pkey) {
  // Nothing
}

static int hmac_set_priv_raw(EVP_PKEY *pkey, const uint8_t *privkey, size_t privkey_len, const uint8_t *pubkey, size_t pubkey_len) {
  // TODO save key here
  return 1;
}

const EVP_PKEY_ASN1_METHOD hmac_asn1_meth = {
    EVP_PKEY_HMAC,
  // TODO(awslc): this is a placeholder OID. Do we need OID for KEM at all?
  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  11,
  NULL, // pub_decode
  NULL, // pub_encode
    NULL,
  NULL, // priv_decode
  NULL, // priv_encode
  NULL, // priv_encode_v2
    hmac_set_priv_raw,
    NULL,
    NULL,
    NULL,
  NULL, // pkey_opaque
  NULL, // kem_size
  NULL, // kem_bits
  NULL, // missing_parameters
  NULL, // param_copy
    NULL,
  hmac_key_free,
};
