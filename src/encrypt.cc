#include <iostream>
#include "aes.h"
#include "generator.h"
#include "sha.h"

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cout << "Usage: ./encrypt input_file output_file\n";
    return 0;
  }

  unsigned char hash[64];
  SHA{}.hash(argv[1], hash);
  std::cout << "SHA-512: ";
  for (unsigned char c : hash) {
    printf("%.2x", c);
  }
  std::cout << std::endl;

  unsigned char key[KEYBYTES];
  unsigned char iv[KEYBYTES];
  Generator generator{};
  generator.generate_aes_key(key);
  generator.generate_iv(iv);

  AES aes{};
  aes.encrypt("input.txt", "output.txt", key, iv);
}
