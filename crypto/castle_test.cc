#include <gtest/gtest.h>
#include <openssl/rust_castle.h>


static void print_hex(const std::vector<uint8_t>& data) {
  for (const auto& byte : data) {
      std::cout << std::hex << std::uppercase << std::setw(2) 
                << std::setfill('0') << static_cast<int>(byte) << " ";
  }
  std::cout << std::endl;
}

TEST(CastleTest, Integrity) {
  const size_t digest_size = 32;
  std::vector<uint8_t> digest_buffer(digest_size);
  
  // Call the Rust function
  ASSERT_TRUE(AWS_LC_FIPS_get_digest(digest_buffer.data(), digest_buffer.size()));
  print_hex(digest_buffer);
  ASSERT_EQ((size_t)17, AWS_LC_FIPS_check_integrity());
}
