#include "generator.h"
#include <stdexcept>
#include "constants.h"

Generator::Generator() {
  mbedtls_entropy_init(&entropy_);
  mbedtls_ctr_drbg_init(&ctr_drbg_);
  if (mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                            entropy_source_, sizeof entropy_source_) != 0) {
    throw std::runtime_error("MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED");
  }
}

std::vector<unsigned char> Generator::generate_random_bytes() {
  std::vector<unsigned char> key(KEY_BYTES);
  switch (mbedtls_ctr_drbg_random(&ctr_drbg_, key.data(), KEY_BYTES)) {
    case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
      throw std::runtime_error("MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED");
    case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
      throw std::runtime_error("MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG");
    case 0:
      return key;
    default:
      throw std::runtime_error("unexpected error in generate_random_bytes");
  }
}
