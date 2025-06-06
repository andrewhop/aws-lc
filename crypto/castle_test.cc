#include <gtest/gtest.h>
#include <openssl/rust_castle.h>

TEST(CastleTest, AddDouble) {
  // Test basic addition
  EXPECT_EQ(aws_lc_add_double(2, 3), 5);
  
  // Test with zero
  EXPECT_EQ(aws_lc_add_double(0, 5), 5);
  EXPECT_EQ(aws_lc_add_double(5, 0), 5);
  EXPECT_EQ(aws_lc_add_double(0, 0), 0);
  
  // Test with large numbers
  EXPECT_EQ(aws_lc_add_double(UINT64_MAX - 10, 5), UINT64_MAX - 5);
  
  // Test overflow behavior (should wrap around)
  EXPECT_EQ(aws_lc_add_double(UINT64_MAX, 1), 0);
  EXPECT_EQ(aws_lc_add_double(UINT64_MAX, 2), 1);
  
  // Test with various combinations
  EXPECT_EQ(aws_lc_add_double(42, 58), 100);
  EXPECT_EQ(aws_lc_add_double(1000, 234), 1234);
}
