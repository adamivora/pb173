encrypt: encrypt.cc sha.cc aes.cc generator.cc
	$(CXX) -I. -lmbedcrypto -std=c++17 -Wall -Wextra -Weffc++ -pedantic -Wold-style-cast -o encrypt encrypt.cc sha.cc aes.cc generator.cc

tidy: 
	clang-tidy *.cc -- -std=c++17
