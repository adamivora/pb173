#ifndef PB173_TEST_HELPERS_H_
#define PB173_TEST_HELPERS_H_
#include <string>
#include <vector>
#include "aes_crypt.h"

std::string to_hex(const std::vector<unsigned char> &bytes);

std::vector<unsigned char> from_hex(const std::string &input);

std::string get_ciphertext(const std::string &key, const std::string &iv,
                           const std::string &plaintext, AES &aes);

std::string get_plaintext(const std::string &key, const std::string &iv,
                          const std::string &ciphertext, AES &aes);
#endif  // PB173_TEST_HELPERS_H_
