cipher: cipher.cc sha.cc aes.cc generator.cc
	$(CXX) -g -I./mbedtls -std=c++17 -Wall -Wextra -Weffc++ -pedantic -Wold-style-cast -o cipher cipher.cc sha.cc aes.cc generator.cc

tidy: 
	clang-tidy *.cc -- -std=c++17
