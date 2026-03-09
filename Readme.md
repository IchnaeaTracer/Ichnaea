# Ichnaea

## Introduction
Ichnaea is a runtime memory object tracing tool that works without instrumentation. It does require adding an API call to register objects for tracing.

## Features
- Traces heap (read/write) and global (read/write) objects during runtime of any C/C++ application
- Needs Recompilation with minimal code changes (adding registration calls)
- Uses MPKs for access control

## Requirements
- Linux (Mostly tested on Debian based systems)
- GCC
- The application **can** be compiled with `-rdynamic` flag (this helps to get symbol names during runtime)
- The application does not use custom signal handlers for SIGSEGV and SIGTRAP
- `libunwind` library should be installed (sudo apt install libunwind-dev)
- `libcapstone` will be built locally from source (no need to install system wide)

## Control Flags
There are a lot of control flags that should be setup before building Ichnaea (libtracer.so). The flags are defined in `tracer.h` file. Some of the important flags are:

- `ENABLE_LOGGING`                          1           : Enable logging of object accesses to disk
- `PRINT_STATE_INFO`                        0           : Enable printing of state information
- `ALLOC_DBG`                               0           : Enable allocation debugging prints
- `ENABLE_WARNINGS`                         0           : Enable warnings for debugging

- `MAX_OBJ_COUNT`                           100         : Max number of objects that can be traced/registered
- `MAX_INTERRUPT_CONTEXTS`                  64          : Max number of interrupt contexts (threads at once)
- `MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT`       20          : Max call stack depth for snapshots
- `MAX_METADATA_BUFFER_SIZE`                600 * 1024  : The max file size for the metadata json file (KiBs)
- `DISABLE_CRITICAL_LOGGING`                0           : Disable even the most critical prints statements (e.g. errors, warnings, etc.)
- `OBJSNF_MAX_SNAPSHOTS_PER_OBJECT`         2000        : Max number of snapshots to store in memory per object (overflow causes error)
- `ICHNAEA_TRACE_READS`                   1           : Trace read accesses to the objects (if disabled, only write accesses are traced)


## Installation

To install the tool, follow these steps:

```bash
$sudo apt update
$sudo apt install make gcc git cmake

# Clone the source code

$git clone <this repo>
$cd object_sniffer
$make install_deps  # Install dependencies
$make
```

## Usage

A test program (see below) can be run with two simple commands:

```bash
$make run_example
```
But if you wanna create your own test program to see how the tracing works, you can create a C file with the following content:
```c
#include <stdio.h>
#include "../tracer.h" // INCLUDE THIS HEADER FILE
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

// Traced Global variable, must be page aligned by adding the PG_ALIGN macro
ICHNAEA_ISOLATE_GLOBAL int global_var = 0; // THIS ALIGNMENT IS OPTIONAL

int main() {


    // Traced Heap variable (no alignment needed)
    char * heap_buffer = malloc(100);

    /* 
     * Registering the variables for tracing
     * After this call, the variables are traced and logged automatically
     * - Must be done before any modification
     */
    ichnaea_register_object  (&global_var, sizeof(global_var) , "global" , "int");    // Global variable 
    ichnaea_register_object  (heap_buffer, 100 , "heap var" , "char *");                    // Heap variable

    /* Modifying the Global variables */

    // 1st modification
    global_var++;
    printf("Global variable after 1st modification: %d\n", global_var);
    // 2nd modification
    global_var = 700;
    printf("Global variable after 2nd modification: %d\n", global_var);


    /* Modifying the Heap variables */

    int fd = open("/proc/cmdline", O_RDONLY);

    // Syscall modifying the heap variable (1st modification)
    int bytes_read = read( fd, heap_buffer, 50);

    // Modifying the heap variable 
    // (2nd modification, no affect on string but will still be logged )
    heap_buffer[bytes_read] = '\0';

    printf("Heap buffer after 1st modification: %s\n", heap_buffer);
 
    return 0;
}
```

once you've created the file (say its named `example_trace.c`). Then, you can compile and run it by:

```bash
$ make # Builds the wrapper library libtracer.so in the current directory
$ gcc example_trace.c -o example_trace -ldl -lunwind -rdynamic // the -rdynamic flag is optional
$ LD_PRELOAD=./libtracer.so ./example_trace
$ # Look at the json files generated for the traced objects
```
## Understanding the output
After running the example, a directory by the name of `objsnf_snapshots` will be created in the current working directory. 

**For traced object**, this directory will contain:

- **Binary Snapshot File**
  - A binary file contaning the binary snapshot of the traced object at each modification (read/write) in order. Say the object was 8 Bytes and was modified 3 times, then this file for that object will be 3 x8 = 24 Bytes. You can decode this file to get the value of the object at each modification (read/write) see later section on how to decode the binary files.
  - you can find the number of snapshots for each object from the metadata file for that object (see the next point)
  - Their name starts with `bin_data@`
- **JSON Metadata** of the traced variables
  - A json file containing human readable information about the traced object and its snapshots. This includes the name, size, runtime address of the object, and the call stack information for each snapshot.
  - Their name starts with `metadata@`

The filename format for each snapshot (binary file) is as follows:
```
obj@<object's_runtime_addr>
[size:<object's_size>] 
[name:<object's_name>] \\ Object name given while registering the object
[snap:<snapshot_number>] \\ Snapshot number (the number wont we consecutive but will be in order of the modification)

```
You can take a look at the metatdata files (json format) for human readable information about the traced objects and their snapshots. You might need `aadr2line` or `nm` to decode some of the stack addresses to get the function names and line numbers.

## Decoding the binary Data

You can decode the **binary** files by frist sliping them into eaqual parts as to the number of snapshots and then
using python's `struct` module. The following code can be used to decode the files:
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

        # Split data into parts accoding to the num_of_snapshots
        # Since you know the size of the struct, you can split the data into parts accordingly
        data_parts = [data[i:i+struct.calcsize(struct_format)] for i in range(0, len(data), struct.calcsize(struct_format))]
        
        for snap_data in data_parts:
          # Unpack the snap_data
          name, size, snap, addr = struct.unpack(struct_format, snap_data)
          
          # Decode the name from bytes to string
          name = name.decode('utf-8').rstrip('\x00')  # Remove null characters
          
          # Print the unpacked snap_data
          print(f"Name: {name}, Size: {size}, Snap: {snap}, Addr: {addr}")
```
