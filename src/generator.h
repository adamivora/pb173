#ifndef PB173_GENERATOR_H_
#define PB173_GENERATOR_H_
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "constants.h"

class Generator {
 private:
  mbedtls_ctr_drbg_context ctr_drbg_{};
  mbedtls_entropy_context entropy_{};
  const unsigned char entropy_source_[10] = {134, 70,  71,  166, 233,
                                             204, 210, 225, 221, 233};
  void generate_random_bytes(unsigned char key[KEYBYTES]);

 public:
  Generator();

  void generate_aes_key(unsigned char key[KEYBYTES]) {
    generate_random_bytes(key);
  }

  void generate_iv(unsigned char iv[KEYBYTES]) { generate_random_bytes(iv); }

  ~Generator() {
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
  }
};

#endif  // PB173_GENERATOR_H_
