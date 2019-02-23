#ifndef PB173_SHA_H_
#define PB173_SHA_H_
#include <mbedtls/sha512.h>
#include <string>

class SHA {
 private:
  static const unsigned int BUFFER_SIZE = 64;
  mbedtls_sha512_context context_;

 public:
  SHA() { mbedtls_sha512_init(&context_); }

  void hash(const std::string &input_filename, unsigned char output[64]);

  ~SHA() { mbedtls_sha512_free(&context_); }
};

#endif  // PB173_SHA_H_
