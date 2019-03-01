#include <iomanip>
#include <sstream>
#include "aes_crypt.h"
#include "catch.hpp"
#include "test-helpers.h"

#define MBEDTLS_CIPHER_PADDING

TEST_CASE("test vectors for encryption") {
  AES aes;

  REQUIRE("dc43be40be0e53712f7e2bf5ca707209" ==
          get_ciphertext("00000000000000000000000000000000",
                         "00000000000000000000000000000000",
                         "6a118a874519e64e9963798a503f1d35", aes));

  REQUIRE("a9a1631bf4996954ebc093957b234589" ==
          get_ciphertext("00000000000000000000000000000000",
                         "00000000000000000000000000000000",
                         "9798c4640bad75c7c3227db910174e72", aes));

  REQUIRE("6d251e6944b051e04eaa6fb4dbf78465" ==
          get_ciphertext("10a58869d74be5a374cf867cfb473859",
                         "00000000000000000000000000000000",
                         "00000000000000000000000000000000", aes));

  REQUIRE("c3b44b95d9d2f25670eee9a0de099fa3" ==
          get_ciphertext("a2e2fa9baf7d20822ca9f0542f764a41",
                         "00000000000000000000000000000000",
                         "00000000000000000000000000000000", aes));
}

TEST_CASE("test vectors for decryption") {
  AES aes;
}

TEST_CASE("file not exists or cannot be read/written into") {}

TEST_CASE("encrypt  ed blob was corrupted") {}

TEST_CASE("wrong decryption key was used") {}
