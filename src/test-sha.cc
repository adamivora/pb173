#include <iomanip>
#include <sstream>
#include "catch.hpp"
#include "sha_crypt.h"
#include "test-helpers.h"

TEST_CASE("test vectors for hashing") {
  SHA sha;

  std::istringstream empty;
  REQUIRE(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c"
      "5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" ==
      to_hex(sha.hash(empty)));

  std::istringstream dog{"dog"};
  REQUIRE(
      "3bbed9c106ceaea9e1d1f851b493a52582ae6f6deab8170da43da346a8710622b21d6c2c"
      "a14c6336bdc770f161673bef5edad6e65d86b05be62817bc9088d924" ==
      to_hex(sha.hash(dog)));

  std::istringstream unicode{"⚾, 🏀, 🌭, 👖"};
  REQUIRE(
      "72a646823648caf5adc9af3efe721e50065fa7d99674db7cf9de0e062b23d5c7a4d4ef15"
      "238db535a18227115852060bc6639bfdc3a88c159da1b5d2a82e4ff5" ==
      to_hex(sha.hash(unicode)));

  std::istringstream very_long{std::string(10000, 'a')};
  REQUIRE(
      "0593036f4f479d2eb8078ca26b1d59321a86bdfcb04cb40043694f1eb0301b8acd20b936"
      "db3c916ebcc1b609400ffcf3fa8d569d7e39293855668645094baf0e" ==
      to_hex(sha.hash(very_long)));
}

TEST_CASE("already read stream") {
  SHA sha;

  std::istringstream already_read{"abc"};
  char buffer[4];
  already_read.read(buffer, 4);

  REQUIRE_THROWS(sha.hash(already_read));
}
