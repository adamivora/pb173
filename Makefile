# Makefile example
# Variables CC and CXX are automatically set on all UNIX systems.

# Variable settings
CXXFLAGS=-Wall -Wextra -Weffc++ -pedantic -lmbedcrypto -I./library
SOURCES_GEN=src/aes.cc src/generator.cc src/sha.cc
# Source and object lists for main program
SOURCES_MAIN=$(SOURCES_GEN) src/cipher.cc
OBJECTS_MAIN=$(SOURCES_MAIN:.cpp=.o)
# Source and object lists for testing binary
SOURCES_TEST=$(SOURCES_GEN) src/testing.cc
OBJECTS_TEST=$(SOURCES_TEST:.cpp=.o)

# Most frequently used automatic variables:
# $@ (name of the target rule)
# $< (name of the first prerequisite)
# $^ (name of all the prerequisites)

# Target anatomy:
# name: dependency1 dependency2
# <tab> command to run
# <tab> other command to run

# Target 'all' has 'main' and 'main-test' as dependencies.
# It is the first defined target (so it's run if no target is specified from CLI).
all: cipher cipher-test

# Depends on main-test, runs the test program.
test: cipher-test
	./cipher-test

# Depends on all object files and main, links the final binary.
cipher: $(OBJECTS_MAIN)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Depends on all object files and test, links the test binary.
cipher-test: $(OBJECTS_TEST)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Automatic rule for all object files in build directory
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJECTS_MAIN) $(OBJECTS_TEST)
