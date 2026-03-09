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