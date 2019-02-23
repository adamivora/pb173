#ifndef PB173_AES_H_
#define PB173_AES_H_
#include <mbedtls/cipher.h>
#include <string>
#include "constants.h"

class AES {
 private:
  mbedtls_cipher_context_t context_;

 public:
  AES();

  void encrypt(const std::string &input_filename,
               const std::string &output_filename,
               const unsigned char aes_key[KEYBYTES],
               const unsigned char iv[KEYBYTES]);

  ~AES() { mbedtls_cipher_free(&context_); }
};

#endif  // PB173_AES_H_
