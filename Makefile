# This makefile create a shared object called libtracer.so

# Compiler and flags
CC = gcc 

# Source files
tracer_src = tracer.c
wrapper_src = wrapper.c wrap-allocs.c wrap-syscalls.c
# library_name = libtracer_test.so
library_name = libtracer.so # ONLY uncomment when doing production build
# library_name = trace_less_libtracer_test.so # Wrap only instrumentation
CFLAGS = -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wstringop-overflow=4 -Warray-bounds -fanalyzer -ffreestanding -fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-bzero

# Header file paths
CFLAGS += -I./libs/libcapstone-main/include/

# Static library (.a) paths
CFLAGS += -L./libs/libcapstone-main

# Shell greeen 
GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
BOLD = "\033[1m"
NC = "\033[0m" # No Color

# Try to find sudo otherwise replacde it with enpty string
SUDO := $(shell which sudo 2>/dev/null || echo "")

all: $(library_name)

# compute once at parse time
EN_PKU := $(shell grep -qw pku /proc/cpuinfo && echo 1 || echo 0)
export EN_PKU


extract_libc_calls:
	@echo "Extracting libc calls..."
	objdump -R @ | grep ' R_X86_64_JUMP_SLOT' | awk '{print $$2}' > libc_calls.txt

# Buluild custom libcapstone
build_libcapstone:
	@echo "Building custom libcapstone..."
	cd libs/libcapstone-main && make

# Compile the example program
example: experiments/example.c
	$(CC) -ggdb -rdynamic  -o $@ experiments/example.c

# Compile tracer and wrapper into a shared object (depends on libcapstone being built)
$(library_name): $(tracer_src) $(wrapper_src) build_libcapstone
	$(info CPU supports PKU : $(if $(filter 1,$(EN_PKU)),Yes,No))
# 	If PKU isn't supported, we stop the build and print an error message
	@if [ $(EN_PKU) -eq 0 ]; then \
		printf -- "\n\n-------------------------------------------------\n"; \
		printf -- "\033[31mError: CPU does not support Memory Protection Keys. Please use a compatible CPU\033[0m\n"; \
		printf -- "-------------------------------------------------\n"; \
		exit 1; \
	fi
	@echo " "
	$(CC) -shared -ggdb  -DOBJSNF_ENABLE_PKEY_BASED_LOCK=$(EN_PKU) -fPIC $(CFLAGS) -o $@ $(tracer_src) $(wrapper_src) -ldl -lelf -lcapstone -lunwind -lunwind-x86_64

run_example: example $(library_name)
	@echo $(BOLD)"\n\n\n-------------------------------"
	@echo $(BLUE)"Running tests..."$(NC)
	@echo $(BOLD)"-------------------------------\n"$(NC)
	LD_PRELOAD=./$(library_name) ./example
	@echo $(BOLD)"\n-------------------------------"$(NC)
	@echo $(GREEN)"Tests completed."$(NC)

run_example_simple: example $(library_name)
	@echo $(BLUE)"Running simple example tests..."$(NC)
	LD_PRELOAD=./$(library_name) ./example_simple
	@echo $(GREEN)"Simple example Tests completed."$(NC)

install_deps:
	@$(SUDO) apt install -y libunwind-dev
	@$(SUDO) apt install -y libelf-dev
	@$(SUDO) apt install -y python3 python3-pyelftools python3-numpy


# test: $(library_name)
# 	@echo "Compiling tests..."
# 	$(CC) -ggdb tests/test1.c -o t1
# 	@echo "Running tests..."
# 	LD_PRELOAD=./$(library_name) ./t1
# 	python3 decode3.py objsnf_snapshots/ -d
# 	python3 tests/test1.py discovered_object*
# 	@echo "Tests completed."
# 	rm -f t1

.PHONY: clean
clean:
	@ rm -f $(library_name)
	@ rm -f *.o
	@ rm -f *.a
	@ rm -f *.so.*
	@ rm -rf objsnf_snapshots
	@ rm -rf example example_simple
	@ rm -f discovered_objects*
	@ rm -f lex
	@ rm -f t1
	@ rm -rf raw_snaps_*