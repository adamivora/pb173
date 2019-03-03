#include <fstream>
#include <iomanip>
#include <sstream>
#include "aes_crypt.h"
#include "catch.hpp"
#include "test-helpers.h"

#define MBEDTLS_CIPHER_PADDING

static AES aes;
static std::vector<unsigned char> default_key =
    from_hex("00000000000000000000000000000000");
static std::vector<unsigned char> default_iv =
    from_hex("00000000000000000000000000000000");

TEST_CASE("test vectors for encryption") {
  CHECK("dc43be40be0e53712f7e2bf5ca707209" ==
        get_ciphertext("00000000000000000000000000000000",
                       "00000000000000000000000000000000",
                       "6a118a874519e64e9963798a503f1d35", aes));

  CHECK("a9a1631bf4996954ebc093957b234589" ==
        get_ciphertext("00000000000000000000000000000000",
                       "00000000000000000000000000000000",
                       "9798c4640bad75c7c3227db910174e72", aes));

  CHECK("6d251e6944b051e04eaa6fb4dbf78465" ==
        get_ciphertext("10a58869d74be5a374cf867cfb473859",
                       "00000000000000000000000000000000",
                       "00000000000000000000000000000000", aes));

  CHECK("c3b44b95d9d2f25670eee9a0de099fa3" ==
        get_ciphertext("a2e2fa9baf7d20822ca9f0542f764a41",
                       "00000000000000000000000000000000",
                       "00000000000000000000000000000000", aes));
}

TEST_CASE("test vectors for decryption") {
  CHECK("00000000000000000000000000000000" ==
        get_plaintext("80000000000000000000000000000000",
                      "00000000000000000000000000000000",
                      "0edd33d3c621e546455bd8ba1418bec8", aes));

  CHECK("00000000000000000000000000000000" ==
        get_plaintext("c0000000000000000000000000000000",
                      "00000000000000000000000000000000",
                      "4bc3f883450c113c64ca42e1112a9e87", aes));

  CHECK("00000000000000000000000000000000" ==
        get_plaintext("ffffffffffffffffffffffffffffe000",
                      "00000000000000000000000000000000",
                      "323994cfb9da285a5d9642e1759b224a", aes));

  CHECK("00000000000000000000000000000000" ==
        get_plaintext("fffffffffffffffffffffffffffff000",
                      "00000000000000000000000000000000",
                      "1dbf57877b7b17385c85d0b54851e371", aes));
}

TEST_CASE("file not exists or cannot be read/written into") {
  SECTION("stream cannot be read from") {
    std::ifstream input;
    input.close();
    std::ostringstream output;

    CHECK_THROWS(aes.encrypt(input, output, default_key, default_iv));
  }

  SECTION("stream cannot be written into") {
    std::istringstream input{"foo"};
    std::ofstream output;
    output.close();

    CHECK_THROWS(aes.encrypt(input, output, default_key, default_iv));
  }
}

TEST_CASE("wrong decryption key was used") {
  SECTION("invalid key length") {
    CHECK_THROWS(get_plaintext("d3adb33f", "00000000000000000000000000000000",
                               "1dbf57877b7b17385c85d0b54851e371", aes));
  }

  SECTION("invalid iv length") {
    CHECK_THROWS(get_plaintext("00000000000000000000000000000000", "d3adb33f",
                               "1dbf57877b7b17385c85d0b54851e371", aes));
  }
}
