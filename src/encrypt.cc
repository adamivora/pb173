#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/sha512.h"

class Generator {
 private:
  mbedtls_ctr_drbg_context ctr_drbg_{};
  mbedtls_entropy_context entropy_{};
  const unsigned char entropy_source_[10] = {134, 70,  71,  166, 233,
                                             204, 210, 225, 221, 233};
  static const unsigned int KEYBITS = 128;
  static const unsigned int KEYBYTES = KEYBITS / sizeof(unsigned char);

 public:
  Generator() {
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_entropy_init(&entropy_);
  }

  void generate_aes_key(unsigned char key[KEYBYTES]) {
    if (mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                              entropy_source_, sizeof entropy_source_) != 0) {
      throw std::runtime_error("MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED");
    }

    switch (mbedtls_ctr_drbg_random(&ctr_drbg_, key, KEYBYTES)) {
      case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
        throw std::runtime_error("MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED");
      case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
        throw std::runtime_error("MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG");
      case 0:
        return;
    }
  }

  ~Generator() {
    mbedtls_entropy_free(&entropy_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
  }
};

class SHA {
 private:
  static const unsigned int BUFFER_SIZE = 64;
  mbedtls_sha512_context context_;

 public:
  SHA() { mbedtls_sha512_init(&context_); }

  void hash(const std::string &input_filename, unsigned char output[64]) {
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

  ~SHA() { mbedtls_sha512_free(&context_); }
};

/*class AES {
 private:
  mbedtls_aes_context context_;

 public:
  AES() { mbedtls_aes_init(&context_); }

  void encrypt(const std::string &input_filename,
               const std::string &output_filename,
               const unsigned char aes_key[KEYBYTES]) {
    mbedtls_aes_setkey_enc(&context_, aes_key, KEYBITS);

    std::ifstream input{input_filename};
    if (!input) {
      throw std::runtime_error("cannot read input file");
    }

    char buffer[KEYBYTES]{};
    unsigned char output_buffer[KEYBYTES];
    input.read(buffer, sizeof buffer);
    mbedtls_aes_crypt_cbc(&context_, MBEDTLS_AES_ENCRYPT, , buffer,
                          output_buffer);
  }

  ~AES() { mbedtls_aes_free(&context_); }
};*/

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cout << "Usage: ./encrypt input_file output_file\n";
    return 0;
  }

  unsigned char hash[64];
  SHA{}.hash(argv[1], hash);
  for (int i = 0; i < 64; i++) printf("%.2x", hash[i]);
  std::cout << std::endl;

  /*unsigned char key[KEYBYTES];
  Generator{}.generate_aes_key(key);
  AES aes{};
  aes.encrypt("input.txt", "output.txt", key);*/
}
