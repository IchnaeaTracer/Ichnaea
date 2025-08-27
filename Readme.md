# Ichnaea

## Introduction
Ichnaea is a runtime memory object tracing tool that uses no instrumentation.

## Requirements
- Linux
- GCC (&Glibc)
- The application does not use custom signal handlers for SIGSEGV and SIGTRAP

## Usage

Example program to trace:
```c
#include <stdio.h>
#include "tracer.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>


ICHNAEA_ISOLATE_GLOBAL int global_var = 0;
char * heap_buffer;

int main() {

    ICHNAEA_MARK_PTR(heap_buffer); // Marking heap_buffer so stores aren't optmized away

    printf( "Heap buffer's pointer's address: %p\n", (void *)&heap_buffer);
    objsnf_register_object(&heap_buffer, sizeof(char *) , "hi" , "char*");
    heap_buffer = malloc(7000); // node on a linked list
    
    /* 
     * Registering the variables for tracing
     * After this call, the variables are traced and logged automatically
     * - Must be done before any modification of traces will be lost
     * - Registration should ideally be done in main
     */

    objsnf_register_object(&global_var, sizeof(global_var) , "global" , "int");// Global variable
    // Pointer which would hold a reference to a heap buffer, Ichnaea will automatically detect allocations made to it an trace them
    objsnf_register_object(&heap_buffer, 7000 , "heap_buffer" , "char*");     

    printf("\nAddress of: \n  Global Var:\t%p(%ldbytes)\n  Heap_buffer:\t%p(%ldbytes)\n", &global_var, sizeof(global_var), heap_buffer, 700LU);


    /* Modifying the Global variables */

    // 1st modification
    printf("Modifying global variable...\n");
    
    global_var++;


    printf("\nGlobal variable after 1st modification: %d\n", global_var);
    // 2nd modification

    printf("Modifying global variable ...\n");
    global_var = 100;

    printf("\nGlobal variable after 2nd modification: %d\n\n", global_var);

    /* Modifying the Heap objects */

    int fd = open("experiments/hi.txt", O_RDONLY);

    // Syscall modifying the heap object (1st modification)
    printf("Modifying heap object... (via read syscall)\n");
    int bytes_read = read( fd, heap_buffer, 50);

    printf("\nHeap buffer after 1st modifications: %s\n", heap_buffer);

    // Modifying the heap object
    // (2nd modification, no visible affect on string but will still be logged )
    printf("Modifying heap object again...\n");

    heap_buffer[bytes_read] = '!';
    heap_buffer[bytes_read+1] = '\0';
    
    printf("\nHeap buffer after 2 modifications: %s\n", heap_buffer);

    return 0;
}

```

### Test Build

We first need to build the wrapper by:
```bash
$ make #LD_PRELOAD wrapper to aid in tracing
$ make run_example #Build and run the example
$ ./decode3.py objsnf_snapshots
$ # Look at the json file discovered_objects_xxx.json
```

After running the example, a directory by the naem of `objsnf_snapshots` will be created in the current working directory. The directory will contain the snapshots of the traced variables.

The filename format for each snapshot (binary file) is as follows:
```
obj@<object's_runtime_addr>
[size:<object's_size>] 
[name:<object's_name>] \\ Object name given while registering the object
[snap:<snapshot_number>] \\ Snapshot number (the number wont we consecutive but will be in order of the modification)

```

You can decode the files using python's `struct` module. The following code can be used to decode the files:
```python
import os
import struct   # For unpacking binary data
import glob

# Say your struct object is of type
# struct objsnf_object {
#     char name[32];
#     int size;
#     int snap;
#     void *addr;
# };

# Define the struct format
struct_format = '32siiP'  # 32 bytes for name, 2 ints for size and snap, and a pointer for addr

# Get the list of all files in the directory
files = glob.glob('objsnf_snapshots/*')

# Loop through each file
for file in files:
    with open(file, 'rb') as f:
        # Read the binary data
        data = f.read(struct.calcsize(struct_format))
        
        # Unpack the data
        name, size, snap, addr = struct.unpack(struct_format, data)
        
        # Decode the name from bytes to string
        name = name.decode('utf-8').rstrip('\x00')  # Remove null characters
        
        # Print the unpacked data
        print(f"Name: {name}, Size: {size}, Snap: {snap}, Addr: {addr}")
```

## TODOs
1. Measure performance impact
2. Optimize for speed
3. Verify/Double Check thread safety
