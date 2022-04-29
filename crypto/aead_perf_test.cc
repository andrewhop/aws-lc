#include <asm/unistd.h>
#include <gtest/gtest.h>
#include <linux/perf_event.h>
#include <openssl/aead.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include "internal.h"


static int startInstructionCounter(perf_event_attr *pAttr) {
  memset(pAttr, 0, sizeof(struct perf_event_attr));
  pAttr->type = PERF_TYPE_HARDWARE;
  pAttr->size = sizeof(struct perf_event_attr);
  pAttr->config = PERF_COUNT_HW_INSTRUCTIONS;
  pAttr->disabled = 1;
  pAttr->exclude_kernel = 1;
  pAttr->exclude_hv = 1;

  int fd = syscall(__NR_perf_event_open, pAttr, 0, -1, -1, 0);
  if (fd == -1) {
    printf("perf_event_open failed %s\n", strerror(errno));
    exit(1);
  }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  return fd;
}

static ssize_t getInstructionCount(int fd) {
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  ssize_t count = 0;
  ssize_t result = read(fd, &count, sizeof(long long));
  if (count < 0 || result < 0) {
    printf("Failed to read instructions, count: %zd, result: %zd", count,
           result);
    exit(1);
  }
  return count;
}

TEST(PerfTest, BasicAESAEAD) {
  alignas(16) uint8_t key[EVP_AEAD_MAX_KEY_LENGTH + 1];
  alignas(16) uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH + 1];
  alignas(16) uint8_t plaintext[32 + 1];
  alignas(16) uint8_t ad[32 + 1];
  alignas(16) uint8_t ciphertext[sizeof(plaintext) + EVP_AEAD_MAX_OVERHEAD];
  size_t ciphertext_len;
  alignas(16) uint8_t out[sizeof(ciphertext)];
  const EVP_AEAD *aead = EVP_aead_aes_256_gcm();
  OPENSSL_memset(key, 'K', sizeof(key));
  OPENSSL_memset(nonce, 'N', sizeof(nonce));
  OPENSSL_memset(plaintext, 'P', sizeof(plaintext));
  OPENSSL_memset(ad, 'A', sizeof(ad));
  const size_t key_len = EVP_AEAD_key_length(aead);
  const size_t nonce_len = EVP_AEAD_nonce_length(aead);
  const size_t ad_len = sizeof(ad) - 1;
  struct perf_event_attr pe;
  for (int i = 0; i < 100; i++) {
    // Start the timer
    int fd = startInstructionCounter(&pe);

    // Do a bunch of crypto
    bssl::ScopedEVP_AEAD_CTX ctx;
    ASSERT_TRUE(EVP_AEAD_CTX_init_with_direction(
        ctx.get(), aead, key + 1, key_len, EVP_AEAD_DEFAULT_TAG_LENGTH,
        evp_aead_seal));
    ASSERT_TRUE(EVP_AEAD_CTX_seal(ctx.get(), ciphertext + 1, &ciphertext_len,
                                  sizeof(ciphertext) - 1, nonce + 1, nonce_len,
                                  plaintext + 1, sizeof(plaintext) - 1, ad + 1,
                                  ad_len));
    ctx.Reset();
    ASSERT_TRUE(EVP_AEAD_CTX_init_with_direction(
        ctx.get(), aead, key + 1, key_len, EVP_AEAD_DEFAULT_TAG_LENGTH,
        evp_aead_open));
    size_t out_len;
    ASSERT_TRUE(EVP_AEAD_CTX_open(ctx.get(), out + 1, &out_len, sizeof(out) - 1,
                                  nonce + 1, nonce_len, ciphertext + 1,
                                  ciphertext_len, ad + 1, ad_len));

    // Get the results
    ssize_t result = getInstructionCount(fd);
    printf("Loop %3d used %zd instructions\n", i, result);
  }
}
