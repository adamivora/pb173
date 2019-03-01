#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "aes_crypt.h"
#include "constants.h"
#include "generator.h"
#include "sha_crypt.h"

void print_hex(const std::vector<unsigned char> &bytes) {
  for (const auto &byte : bytes) {
    printf("%02x", byte);
  }
}

void print_keys(const std::vector<unsigned char> &hash,
                const std::vector<unsigned char> &aes_key,
                const std::vector<unsigned char> &iv) {
  std::cout << "SHA-512:\n";
  print_hex(hash);
  std::cout << "\nAES key:\n";
  print_hex(aes_key);
  std::cout << "\nIV:\n";
  print_hex(iv);
  std::cout << std::endl;
}

void read_keys(std::istream &input, std::vector<unsigned char> &hash,
               std::vector<unsigned char> &aes_key,
               std::vector<unsigned char> &iv) {
  input.read(reinterpret_cast<char *>(hash.data()), HASH_BYTES);
  input.read(reinterpret_cast<char *>(aes_key.data()), KEY_BYTES);
  input.read(reinterpret_cast<char *>(iv.data()), KEY_BYTES);
  if (!input) {
    throw std::runtime_error("cannot read from input file");
  }
}

void write_keys(std::ostream &output, const std::vector<unsigned char> &hash,
                const std::vector<unsigned char> &aes_key,
                const std::vector<unsigned char> &iv) {
  output.write(reinterpret_cast<const char *>(hash.data()), HASH_BYTES);
  output.write(reinterpret_cast<const char *>(aes_key.data()), KEY_BYTES);
  output.write(reinterpret_cast<const char *>(iv.data()), KEY_BYTES);
  if (!output) {
    throw std::runtime_error("error while writing to output file");
  }
}

void encrypt(const std::string &input_filename,
             const std::string &output_filename) {
  Generator generator{};
  std::vector<unsigned char> key = generator.generate_aes_key();
  std::vector<unsigned char> iv = generator.generate_iv();
  std::ifstream hash_input{input_filename};
  std::vector<unsigned char> hash = SHA{}.hash(hash_input);

  std::ofstream output{output_filename};
  print_keys(hash, key, iv);
  write_keys(output, hash, key, iv);

  std::ifstream input{input_filename};

  AES{}.encrypt(input, output, key, iv);
}

void compare_hashes(const std::vector<unsigned char> expected,
                    const std::string &output_filename) {
  std::ifstream hash_output{output_filename};
  std::vector<unsigned char> actual = SHA{}.hash(hash_output);
  std::cout << "Actual SHA:\n";
  print_hex(actual);

  if (actual == expected) {
    std::cout << "\n\nSHA-512 hashes match." << std::endl;
  } else {
    std::cout << "\n\nSHA-512 hashes DO NOT match." << std::endl;
  }
}

void decrypt(const std::string &input_filename,
             const std::string &output_filename) {
  std::vector<unsigned char> expected_hash(HASH_BYTES), key(KEY_BYTES),
      iv(KEY_BYTES);

  {
    std::ifstream input{input_filename};
    std::ofstream output{output_filename};

    read_keys(input, expected_hash, key, iv);
    print_keys(expected_hash, key, iv);
    AES{}.decrypt(input, output, key, iv);
  }

  compare_hashes(expected_hash, output_filename);
}

int main(int argc, char **argv) {
  if (argc < 4) {
    std::cout << "Usage: ./cipher [encrypt/decrypt] input_file output_file"
              << std::endl;
    return 0;
  }

  std::string operation = argv[1];
  std::string input_filename = argv[2];
  std::string output_filename = argv[3];

  if (operation == "encrypt") {
    encrypt(input_filename, output_filename);
  } else if (operation == "decrypt") {
    decrypt(input_filename, output_filename);
  } else {
    std::cout << "Usage: ./cipher [encrypt/decrypt] input_file output_file"
              << std::endl;
    return 0;
  }
}
