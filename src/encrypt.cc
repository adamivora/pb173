#include <cstdio>
#include <iostream>
#include "mbedtls/md.h"
#include "mbedtls/sha512.h"

int main() {
  const unsigned char input[] = "hello world";
  unsigned char output[64];

  mbedtls_sha512_ret(input, 11, output, 0);
  for (size_t i = 0; i < sizeof output; i++) {
    printf("%02x", output[i]);
  }
  std::cout << std::endl;
}
