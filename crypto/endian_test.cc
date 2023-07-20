#include <gtest/gtest.h>
#include "internal.h"
#include "test/test_util.h"


TEST(EndianTest, u32Operations) {
  uint8_t buffer[4];
  uint32_t val = 0x12345678;
  uint8_t expected_be[4] = {0x12, 0x34, 0x56, 0x78};
  uint8_t expected_le[4] = {0x78, 0x56, 0x34, 0x12};


  CRYPTO_store_u32_le(buffer, val);
  EXPECT_EQ(Bytes(expected_le), Bytes(buffer));
  EXPECT_EQ(val, CRYPTO_load_u32_le(buffer));

  CRYPTO_store_u32_be(buffer, val);
  EXPECT_EQ(Bytes(expected_be), Bytes(buffer));
  EXPECT_EQ(val, CRYPTO_load_u32_be(buffer));
}

TEST(EndianTest, u64Operations) {
  uint8_t buffer[8];
  uint64_t val = 0x123456789abcdef0;
  uint8_t expected_be[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
  uint8_t expected_le[8] = {0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12};

  CRYPTO_store_u64_le(buffer, val);
  EXPECT_EQ(Bytes(expected_le), Bytes(buffer));
  EXPECT_EQ(val, CRYPTO_load_u64_le(buffer));

  CRYPTO_store_u64_be(buffer, val);
  EXPECT_EQ(Bytes(expected_be), Bytes(buffer));
  EXPECT_EQ(val, CRYPTO_load_u64_be(buffer));
}

TEST(EndianTest, wordOperations) {
  uint8_t buffer[sizeof(size_t)];
#if defined(OPENSSL_64_BIT)
  size_t val = 0x123456789abcdef0;
  uint8_t expected_le[8] = {0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12};
#else
size_t val = 0x12345678;
uint8_t expected_le[4] = {0x78, 0x56, 0x34, 0x12};
#endif

  CRYPTO_store_word_le(buffer, val);
  EXPECT_EQ(Bytes(expected_le), Bytes(buffer));
  EXPECT_EQ(val, CRYPTO_load_word_le(buffer));
}

TEST(EndianTest, TestRotate32) {
  uint32_t value = 0b00000010000000000000000000000;
  // 0x12345678  = 0b10010001101000101011001111000
  // Rotate 4    = 0b00110100010101100111100010010
  uint32_t expected = 0b00100000000000000000000000000;

  uint32_t rotl_by = 4;
  uint32_t rotr_by = 32 - rotl_by;

  uint32_t rotl_value = CRYPTO_rotl_u32(value, rotl_by);
  uint32_t rotr_value = CRYPTO_rotr_u32(value, rotr_by);

  ASSERT_EQ(rotl_value, rotr_value);
  EXPECT_EQ(expected, rotl_value);
  ASSERT_EQ(CRYPTO_rotr_u32(rotl_value, rotl_by), value);
}

TEST(EndianTest, TestRotate64) {
  uint64_t value = 0b0000001000000000000000000000000000010000000000000000000000;
  uint64_t expected = 0b0010000000000000000000000000000100000000000000000000000000;

  uint64_t rotl_by = 4;
  uint64_t rotr_by = 64 - rotl_by;

  uint64_t rotl_value = CRYPTO_rotl_u64(value, rotl_by);
  uint64_t rotr_value = CRYPTO_rotr_u64(value, rotr_by);

  ASSERT_EQ(rotl_value, rotr_value);
  EXPECT_EQ(expected, rotl_value);
  ASSERT_EQ(CRYPTO_rotr_u64(rotl_value, rotl_by), value);
}

union test_union {
  uint16_t big[2];
  uint8_t small[4];
};

struct test_struct {
  test_union union_val;
};

TEST(EndianTest, TestStructUnion) {
  struct test_struct val = {{{0}}};
  val.union_val.big[0] = 0x1234;
  val.union_val.big[1] = 0x5678;


#if defined(OPENSSL_BIG_ENDIAN)
  ASSERT_EQ(val.union_val.small[0], 0x12);
  ASSERT_EQ(val.union_val.small[1], 0x34);
  ASSERT_EQ(val.union_val.small[2], 0x56);
  ASSERT_EQ(val.union_val.small[3], 0x78);
#else
  ASSERT_EQ(val.union_val.small[0], 0x34);
  ASSERT_EQ(val.union_val.small[1], 0x12);
  ASSERT_EQ(val.union_val.small[2], 0x78);
  ASSERT_EQ(val.union_val.small[3], 0x56);
#endif
}
