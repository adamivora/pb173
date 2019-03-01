# Makefile example
# Variables CC and CXX are automatically set on all UNIX systems.

# Variable settings
CXXFLAGS=-std=c++17 -Wall -Wextra -Weffc++ -pedantic -I./src
CFLAGS=-std=c99 -Wall -Wextra -pedantic -I./src
SOURCES_ALL=$(wildcard src/*.c) $(wildcard src/*.cc)
SOURCES_GEN=$(filter-out src/main.cc src/testing.cc, $(SOURCES_ALL))

# Source and object lists for main program
SOURCES_MAIN=$(SOURCES_GEN) src/main.cc
OBJECTS_C_MAIN=$(SOURCES_MAIN:.c=.o)
OBJECTS_MAIN=$(OBJECTS_C_MAIN:.cc=.o)

# Source and object lists for testing binary
SOURCES_TEST=$(SOURCES_GEN) src/testing.cc
OBJECTS_C_TEST=$(SOURCES_TEST:.c=.o)
OBJECTS_TEST=$(OBJECTS_C_MAIN:.cc=.o)

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
all: main main-test

# Depends on main-test, runs the test program.
test: main-test
	./main-test

# Depends on all object files and main, links the final binary.
main: $(OBJECTS_MAIN)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Depends on all object files and test, links the test binary.
main-test: $(OBJECTS_TEST)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Automatic rule for all object files in build directory
%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJECTS_MAIN) $(OBJECTS_TEST)
