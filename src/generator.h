#ifndef PB173_GENERATOR_H_
#define PB173_GENERATOR_H_
#include <vector>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

class Generator {
 private:
  mbedtls_ctr_drbg_context ctr_drbg_{};
  mbedtls_entropy_context entropy_{};
  const unsigned char entropy_source_[10] = {134, 70,  71,  166, 233,
                                             204, 210, 225, 221, 233};
  std::vector<unsigned char> generate_random_bytes();

 public:
  Generator();

  std::vector<unsigned char> generate_aes_key() {
    return generate_random_bytes();
  }

  std::vector<unsigned char> generate_iv() { return generate_random_bytes(); }

  ~Generator() {
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
  }
};

#endif  // PB173_GENERATOR_H_
