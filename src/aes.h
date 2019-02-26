#ifndef PB173_AES_H_
#define PB173_AES_H_
#include <iostream>
#include <vector>
#include "mbedtls/cipher.h"

class AES {
 private:
  mbedtls_cipher_context_t context_;
  void init(const std::vector<unsigned char> &aes_key,
            const std::vector<unsigned char> &iv,
            mbedtls_operation_t operation);
  void process(std::istream &input, std::ostream &output);

 public:
  AES();

  void encrypt(std::istream &input_filename, std::ostream &output_filename,
               const std::vector<unsigned char> &aes_key,
               const std::vector<unsigned char> &iv);

  void decrypt(std::istream &input_filename, std::ostream &output_filename,
               const std::vector<unsigned char> &aes_key,
               const std::vector<unsigned char> &iv);

  ~AES() { mbedtls_cipher_free(&context_); }
};

#endif  // PB173_AES_H_
