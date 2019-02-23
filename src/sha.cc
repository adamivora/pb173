#include "sha.h"
#include <fstream>
#include <stdexcept>

void SHA::hash(const std::string &input_filename, unsigned char output[64]) {
  if (mbedtls_sha512_starts_ret(&context_, 0) < 0) {
    throw std::runtime_error("mbedtls_sha512_starts_ret failed");
  }

  std::ifstream input{input_filename};
  if (!input) {
    throw std::runtime_error("cannot read input file");
  }

  unsigned char buffer[BUFFER_SIZE];
  char *b = reinterpret_cast<char *>(buffer);
  int read_bytes;
  while ((read_bytes = input.read(b, BUFFER_SIZE).gcount()) != 0) {
    if (mbedtls_sha512_update_ret(&context_, buffer, read_bytes) < 0) {
      throw std::runtime_error("mbedtls_sha512_update_ret failed");
    }
  }

  if (input.bad()) {
    throw std::runtime_error("input stream error while reading");
  }

  if (mbedtls_sha512_finish_ret(&context_, output) < 0) {
    throw std::runtime_error("mbedtls_sha512_update_ret failed");
  }
}
