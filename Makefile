# This makefile create a shared object called libtracer.so

# Compiler and flags
CC = gcc 

# Source files
tracer_src = tracer.c
wrapper_src = wrapper.c wrap-allocs.c wrap-syscalls.c
library_name = libtracer_test.so

all: $(library_name)

# Compile the example program
example: example.c
	$(CC) -ggdb  -o $@ example.c

# Compile tracer and wrapper into a shared object
$(library_name): $(tracer_src) $(wrapper_src)
	$(CC) -shared -ggdb -fPIC $(CFLAGS) -o $@ $(tracer_src) $(wrapper_src) -ldl -lelf -lcapstone

run_example: clean example $(library_name)
	@echo "Running tests..."
	LD_PRELOAD=./$(library_name) ./example
	@echo "Tests completed."

test: $(library_name)
	@echo "Compiling tests..."
	$(CC) -ggdb tests/test1.c -o t1
	@echo "Running tests..."
	LD_PRELOAD=./$(library_name) ./t1
	python3 decode3.py objsnf_snapshots/ -d
	python3 tests/test1.py discovered_object*
	@echo "Tests completed."
	rm -f t1

.PHONY: clean
clean:
	@ rm -f $(library_name)
	@ rm -f *.o
	@ rm -f *.a
	@ rm -f *.so.*
	@ rm -rf objsnf_snapshots
	@ rm -rf example
	@ rm -f discovered_objects*
	@ rm -f lex
	@ rm -f t1