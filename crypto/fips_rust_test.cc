#include <gtest/gtest.h>
#include <openssl/fips_rust.h>


static void print_hex(const std::vector<uint8_t>& data) {
  for (const auto& byte : data) {
      std::cout << std::hex << std::uppercase << std::setw(2) 
                << std::setfill('0') << static_cast<int>(byte);
  }
  std::cout << std::endl;
}

TEST(Rust, Integrity) {
  const size_t digest_size = 32;
  std::vector<uint8_t> digest_buffer(digest_size);

  // The module must be able to compute the digest of its own code region.
  ASSERT_TRUE(AWS_LC_FIPS_get_digest(digest_buffer.data(), digest_buffer.size()));
  std::cout << "Rust FIPS module digest: 0x";
  print_hex(digest_buffer);

  // A short buffer must be rejected.
  ASSERT_FALSE(AWS_LC_FIPS_get_digest(digest_buffer.data(), digest_size - 1));

  // The boundary self-check must pass: every critical function lies within the
  // module's code boundary.
  ASSERT_EQ(1, AWS_LC_FIPS_check_integrity());
}
