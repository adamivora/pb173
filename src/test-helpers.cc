#include "test-helpers.h"
#include <cstdlib>
#include <iomanip>
#include <sstream>

std::string to_hex(const std::vector<unsigned char> &bytes) {
  std::stringstream stream;
  for (const unsigned char &byte : bytes) {
    stream << std::hex << std::setfill('0') << std::setw(2) << (int)(byte);
  }

  return stream.str();
}

std::vector<unsigned char> from_hex(const std::string &input) {
  std::vector<unsigned char> vector;

  size_t len = input.length();
  for (size_t i = 0; i < len; i += 2) {
    std::stringstream x{input.substr(i, 2)};
    unsigned int c;
    x >> std::hex >> c;
    vector.push_back(c);
  }

  return vector;
}

std::string get_ciphertext(const std::string &key, const std::string &iv,
                           const std::string &plaintext, AES &aes) {
  auto bytes = from_hex(plaintext);
  auto key_bytes = from_hex(key);
  auto iv_bytes = from_hex(iv);

  std::stringstream input{std::string{bytes.begin(), bytes.end()}};
  std::stringstream output;
  aes.encrypt(input, output, key_bytes, iv_bytes, MBEDTLS_PADDING_NONE);

  auto output_str = output.str();

  return to_hex(
      std::vector<unsigned char>(output_str.begin(), output_str.end()));
}

std::string get_plaintext(const std::string &key, const std::string &iv,
                          const std::string &ciphertext, AES &aes) {
  auto bytes = from_hex(ciphertext);
  auto key_bytes = from_hex(key);
  auto iv_bytes = from_hex(iv);

  std::stringstream input{std::string{bytes.begin(), bytes.end()}};
  std::stringstream output;
  aes.decrypt(input, output, key_bytes, iv_bytes, MBEDTLS_PADDING_NONE);

  auto output_str = output.str();

  return to_hex(
      std::vector<unsigned char>(output_str.begin(), output_str.end()));
}
