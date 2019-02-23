#include "aes.h"
#include <mbedtls/cipher.h>
#include <fstream>

AES::AES() {
  mbedtls_cipher_init(&context_);
  switch (mbedtls_cipher_setup(
      &context_, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC))) {
    case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
      throw std::runtime_error("MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA");
    case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
      throw std::runtime_error("MBEDTLS_ERR_CIPHER_ALLOC_FAILED");
  }
}

void AES::encrypt(const std::string &input_filename,
                  const std::string &output_filename,
                  const unsigned char aes_key[KEYBYTES],
                  const unsigned char iv[KEYBYTES]) {
  if (mbedtls_cipher_setkey(&context_, aes_key, KEYBITS, MBEDTLS_ENCRYPT) < 0) {
    throw std::runtime_error("mbedtls_cipher_setkey failed");
  }

  if (mbedtls_cipher_set_iv(&context_, iv, KEYBYTES) < 0) {
    throw std::runtime_error("MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA");
  }

  std::ifstream input{input_filename};
  if (!input) {
    throw std::runtime_error("cannot read input file");
  }

  std::ofstream output{output_filename};
  if (!output.write(reinterpret_cast<const char *>(iv), KEYBYTES)) {
    throw std::runtime_error("cannot access output file");
  }

  unsigned char buffer[KEYBYTES];
  char *b = reinterpret_cast<char *>(buffer);

  unsigned char output_buffer[KEYBYTES];
  char *o = reinterpret_cast<char *>(output_buffer);

  int read_bytes;
  size_t olen;
  while ((read_bytes = input.read(b, KEYBYTES).gcount()) != 0) {
    if (mbedtls_cipher_update(&context_, buffer, read_bytes, output_buffer,
                              &olen) < 0) {
      throw std::runtime_error("mbedtls_cipher_update failed");
    }
    output.write(o, olen);
  }

  if (input.bad()) {
    throw std::runtime_error("input stream error while reading");
  }

  if (mbedtls_cipher_finish(&context_, output_buffer, &olen) < 0) {
    throw std::runtime_error("mbedtls_cipher_finish failed");
  }
  output.write(o, olen);
}
