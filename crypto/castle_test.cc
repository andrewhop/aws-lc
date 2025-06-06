#include <gtest/gtest.h>
#include <openssl/rust_castle.h>

TEST(CastleTest, AddDouble) {
  EXPECT_EQ(aws_lc_add_double(2, 3), (uint64_t)10);
}
