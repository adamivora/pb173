#ifndef PB173_AES_CRYPT_H_
#define PB173_AES_CRYPT_H_
#include <iostream>
#include <vector>
#include "mbedtls/cipher.h"

class AES {
 private:
  mbedtls_cipher_context_t context_;
  void init(const std::vector<unsigned char> &aes_key,
            const std::vector<unsigned char> &iv,
            mbedtls_operation_t operation,
            mbedtls_cipher_padding_t padding_mode);
  void process(std::istream &input, std::ostream &output);

 public:
  AES();

  void encrypt(std::istream &input, std::ostream &output,
               const std::vector<unsigned char> &aes_key,
               const std::vector<unsigned char> &iv,
               mbedtls_cipher_padding_t padding_mode = MBEDTLS_PADDING_PKCS7);

  void decrypt(std::istream &input, std::ostream &output,
               const std::vector<unsigned char> &aes_key,
               const std::vector<unsigned char> &iv,
               mbedtls_cipher_padding_t padding_mode = MBEDTLS_PADDING_PKCS7);

  ~AES() { mbedtls_cipher_free(&context_); }
};

#endif  // PB173_AES_CRYPT_H_
