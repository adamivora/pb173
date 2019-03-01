#include "sha_crypt.h"
#include <iostream>
#include <stdexcept>
#include "constants.h"

std::vector<unsigned char> SHA::hash(std::istream &input) {
  if (mbedtls_sha512_starts_ret(&context_, 0) < 0) {
    throw std::runtime_error("mbedtls_sha512_starts_ret failed");
  }

  if (!input) {
    throw std::runtime_error("cannot read input file");
  }

  std::vector<unsigned char> buffer(HASH_BYTES);
  char *b = reinterpret_cast<char *>(buffer.data());
  int read_bytes;
  while ((read_bytes = input.read(b, HASH_BYTES).gcount()) != 0) {
    if (mbedtls_sha512_update_ret(&context_, buffer.data(), read_bytes) < 0) {
      throw std::runtime_error("mbedtls_sha512_update_ret failed");
    }
  }
  std::cout << std::endl;

  if (input.bad()) {
    throw std::runtime_error("input stream error while reading");
  }

  std::vector<unsigned char> output_buffer(HASH_BYTES);
  if (mbedtls_sha512_finish_ret(&context_, output_buffer.data()) < 0) {
    throw std::runtime_error("mbedtls_sha512_update_ret failed");
  }

  return output_buffer;
}
