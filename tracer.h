/*
    * Ichnaea
    * A C/C++ object tracing and debugging tool
    * Include this header in your C/C++ code to use the tracer
    * After including this header, you can use the following function:
    * int ichnaea_register_object(void *addr, size_t size, char *name, char *type);
    * This function will register the object at the given address with the given size, name and type
    * It will trace the object and log its access
*/

// Flags to enable/disable features
#define PAGE_SIZE 4096LU

/* Batching Flags
    * If you're not sure if the program you're tracing will exit gracefully,
    * then you should disable snapshot batching, as batching will cause the tracer to
    * write all the snapshots at_exit or when either of SIGINT, SIGTERM, SIGQUIT, SIGABRT, SIGFPE are received.
    * With batching disabled, the tracer will write the snapshot immediately when the object is accessed.
    * NOTE: Batching won't work with SIGKILL
*/
#define OBJSNF_ENABLE_SNAPSHOT_BATCHING     1       // Enable snapshot batching for performance
#define OBJSNF_ENABLE_SMART_ALLOCS          1       // Enable smart allocs to reduce the number of mprotect calls

#ifndef OBJSNF_MAX_SNAPSHOTS_PER_OBJECT
#define OBJSNF_MAX_SNAPSHOTS_PER_OBJECT     600      // Max number of snapshots to store in memory per object (overflow causes error)
#endif

#define PRINT_STATE_INFO                    0
#define ENABLE_WARNINGS                     0       // Enable warnings for debugging
// End of Batching Flags
#define MAX_OBJ_COUNT                           100          // Max number of objects that can be traced/registered
#define MAX_INTERRUPT_CONTEXTS                  64           // Max number of interrupt contexts (threads at once)
#define MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT       10           // Max call stack depth for snapshots
#define MAX_METADATA_BUFFER_SIZE                10 * 1024    // The max file size for the metadata json file (Bytes)
#define DISABLE_CRITICAL_LOGGING                1            // Disable even the most critical prints statements (e.g. errors, warnings, etc.)

// This attribute is used to isolate global variables in their own section (Will generate a warning)
#define ICHNAEA_ISOLATE_GLOBAL __attribute__((section (".rodata")))

// Mark a pointer as used so stores aren't optimized away
#define ICHNAEA_MARK_PTR(x) asm volatile ("" : "=m"(x));

// Mark alloc check, checks if the allocation is for a traced object, if not then falls back to actual allocator 
// but if it is the returns freshly allocated memory

#ifndef _OBJSNF_SRC // These definitions are exclusivly for the user

// Some hacks to install definitions for stuff like size_t
/*  If we get here, none of the usual guards fired, so roll our own.
 *  unsigned long is the safest generic choice on 64-bit as well as 32-bit
 *  targets that the SPEC build runs on.  Change if your platform differs.
 */
typedef unsigned long size_t;


/*
    * The only API that is exposed to the user
    * This function registers an object for tracing
    * @param addr: Address of the object to be traced
    * @param size: Size of the object to be traced
    * @param name: Name of the object to be traced
    * @param type: Type of the object to be traced e.g. "int" (detailed structure of the type should be in layouts.json)
    * @return: 0 on success, 1 on failure
    * as
    * Note: This function is weakly linked and gets resolved at runtime by our preloaded wrapper
*/

#ifdef __cplusplus
extern "C" __attribute__((weak)) int objsnf_register_object(void *addr, size_t size , char *name , char *type);
#else
__attribute__((weak)) extern int objsnf_register_object(void *addr, size_t size , char *name , char *type);
#endif


#endif
 

// Assuming page size is 4096 bytes
#define PAGE_SIZE 4096LU
#define GRD_PG_SZ 2 * PAGE_SIZE




// Only internal definitions beyond this point not to be used by the user

// Aligns the variable to a page size
// This is important for mprotect to work correctly for globals and stack variables

#define OBJSNF_PG_ALIGN __attribute__((aligned (PAGE_SIZE)))

#define RESPECT_ORDER __attribute__((no_reorder))

// Macro for adding a guard page on the stack or global (2 pages wide)
#define CONCATENATE_DETAIL(x, y) x##y
#define CONCATENATE(x, y) CONCATENATE_DETAIL(x, y)
#define UNIQUE_NAME(base) CONCATENATE(base, __COUNTER__)
#define GUARD_PAGE_STK volatile char UNIQUE_NAME(__guard_page_stk_id)[GRD_PG_SZ] = {0};
#define WRAP_WTH_GRD_PG_STK(x) \
    OBJSNF_PG_ALIGN RESPECT_ORDER GUARD_PAGE_STK \
    OBJSNF_PG_ALIGN RESPECT_ORDER x; \
    OBJSNF_PG_ALIGN RESPECT_ORDER GUARD_PAGE_STK \



#ifdef _OBJSNF_SRC


#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <dlfcn.h>


// Libc wrapper cannot have these included
// but still needs source definitions
#ifndef _WRAP_PRELOAD_H 

#include <stdlib.h>
#include <signal.h>
#include <ucontext.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <execinfo.h>
#include <capstone/capstone.h>

#include <libelf.h> // Required for EV_CURRENT and other libelf functions
#include <fcntl.h>
#include <link.h>   // Required for struct dl_phdr_info and dl_iterate_phdr
#include <gelf.h>   // Include the header for GElf_Shdr

extern short wrapper_objsnf_dlsym_done;

#endif

#ifndef ENABLE_WARNINGS
#define ENABLE_WARNINGS 0 
#endif

#ifndef PRINT_STATE_INFO
#define PRINT_STATE_INFO 0
#define ALLOC_DBG 0
#define ENABLE_DLINFO 1 // Big runtime overhead
#endif

#ifndef ENABLE_TRACING
#define ENABLE_TRACING 1 
#endif

#ifndef ENABLE_LOGGING
// If logging is enabled, it will create a file for each object that is accessed
#define ENABLE_LOGGING 1
#define PRINT_LOGGING_INFO 0
#endif

#ifndef MAX_OBJ_COUNT
// Max number of objects that can be traced (Must be a multiple of 64)
#define MAX_OBJ_COUNT 32 * 5
#endif

#ifndef MAX_INTERRUPT_CONTEXTS
// Max number of interrupt contexts (threads at once)
#define MAX_INTERRUPT_CONTEXTS 64
#endif

#define MAX_OBJ_NAME_LEN 48
#define MAX_TYPE_NAME_LEN 40 

#define USE_SHELL_COLORING 1

#if USE_SHELL_COLORING
#define GREEN             "\033[0;32m"
#define RED               "\033[0;31m"
#define YELLOW            "\033[0;33m"
#define BLUE              "\033[0;34m"
#define CYAN              "\033[0;36m"
#define MAGENTA           "\033[0;35m"
#define RESET             "\033[0m"
#define BOLD              "\033[1m"
#define TRACER_PRMPT      "\033[0;34mTracer\033[0m: "
#else
#define GREEN             "<p style=\"color:green;\">"
#define RED               "<p style=\"color:red;\">"
#define YELLOW            "<p style=\"color:yellow;\">"
#define BLUE              "<p style=\"color:blue;\">"
#define MAGENTA           "<p style=\"color:magenta;\">"
#define RESET             "</p>"
#define BOLD              "<p style=\"font-weight:bold;\">"
#define TRACER_PRMPT      "<p style=\"color:red;\">Tracer</p>: "
#endif

// Stuff for mesuring time between two points
#define STOP_MEASURING_TIME struct timespec ts_after;clock_gettime(CLOCK_MONOTONIC_RAW, &ts_after);fprintf(stderr, "%ld,", ((int64_t)ts_after.tv_sec - (int64_t)objsnf_gvars.init_time.tv_sec) * (int64_t)1000000000+ ((int64_t)ts_after.tv_nsec - (int64_t)objsnf_gvars.init_time.tv_nsec));
#define START_MEASURING_TIME clock_gettime(CLOCK_MONOTONIC_RAW, &objsnf_gvars.init_time);
// Assumptions | Conditions for this tracer to work
// 1. The application can be compiled with -lcapstone
// 2. The application does not use custom signal handlers for SIGSEGV and SIGTRAP
// 3. all files must be compiled with -rdynamic
// TODO:
// Add more assumptions
// Clean mprotect calls
// Pinpoint data instead if unlocking all
// Find a way to name the objects, mayve statically insert names with crazy?
// Guard pages don't really work 😭 cause gcc is stupid!!
// See if locking if working well for heap objects?
// Fix double locking of objects when registerred


// Assembly macro for writing a string literal to stdout using syscall
#define WRITE_STR_LIT(const_str)                                              \
asm volatile (                                                      \
    /* syscall number = 1 (SYS_write) */                            \
    "mov $1, %%rax         \n\t"                                    \
    /* file descriptor = 1 (stdout) */                              \
    "mov $1, %%rdi         \n\t"                                    \
    /* buffer = address of the string literal */                    \
    "mov %0, %%rsi         \n\t"                                    \
    /* length = (sizeof(str) - 1) */                                \
    "mov %1, %%rdx         \n\t"                                    \
    /* make the syscall */                                          \
    "syscall               \n\t"                                    \
    : /* no outputs */                                              \
    : "r"(const_str), "r"(sizeof(const_str) - 1) /* inputs: pointer, length */  \
    : "rax", "rdi", "rsi", "rdx", "memory", "cc"                    \
)

// Macro for printing line number and file name (used for debugging)
#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define AT_LINE " " __FILE__ " line " STRINGIZE(__LINE__) "\n"

#define FLAG const char str[] = MAGENTA "FLAG!!\n" RESET;WRITE_STR_LIT(  str  );

/* Generic Obj/Ctx Management Structs */

/* 
 * Struct to keep track of traced objects
 * Note:
 *  - This is also used in wrap-preload
 *  - The size of the struct must be a multiple of 64
 */
typedef struct objsnf_traced_objects_t {
    void*   addr;
    unsigned long  size;
    bool    is_un_aligned;
    void*   unaligned_addr;
    unsigned long  unaligned_size;
    char    name[MAX_OBJ_NAME_LEN];
    char    type[MAX_TYPE_NAME_LEN];
    short   snap_count; // Count of how many times this object was accessed
    bool    is_a_reference_pointer; // If this object is a reference pointer to the object of interest
} objsnf_traced_objects_s;


/*
 * Struct to hold the output of an instruction decode
*/
typedef struct {
    int      ok;            // 1 if value computed
    uint64_t value;         // value to store
    unsigned width;         // bytes (1/2/4/8/16/32 for SIMD stores if you extend)
} store_value_t;

/* Array management structure */
enum objsnf_node_state_s {
    END_NODE,
    FREED_NODE,
    IN_USE_NODE,
};

struct interrupt_contexts_t {
    pid_t                               thread_id;          // Identify the ctx by thread id
    void*                               orig_addr;          // Starting addr of the instruction that was modified to an INT3
    unsigned char                       orig_instruction;   // Original instruction byte
    objsnf_traced_objects_s*            object;             // Figure out which object is being accessed
    bool                                is_obj_traced;      // False if the locked obj isn't traced
    enum objsnf_node_state_s            node_state;         // Hackish way of makin a bad linked list
    char                                padding[24];        // Padding to make the struct size a multiple of 4096
};

typedef struct interrupt_contexts_t interrupt_contexts_s;

// Common functions in the tracer and wrapper
objsnf_traced_objects_s*            objsnf_address_within_traced_objects_pg (void * addr_in_question,objsnf_traced_objects_s *traced_objects);
int                                 objsnf_register_object                  (void *addr, size_t size, char *name, char *type);
int                                 objsnf_log_event                        (objsnf_traced_objects_s * obj, bool syscall_dump);


struct snap_metadata_s {
    unsigned long long hash;                              // Hash of the object
    void * call_stack[MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT]; // Call stack at the time of the snapshot
    short call_stack_size;                                // Size of the call stack
    pid_t pid;                                            // Process ID
    pid_t tid;                                            // Thread ID
    bool is_syscall_dump;                                 // Flag to indicate if this is a syscall dump
    void* snap_buffer;                                    // Pointer to the snapshot buffer
};
/*
    * Struct to carry snapshot related metadata
    * This is used to store the hash of the object, call stack at the time of the snapshot, process ID and thread ID
*/
typedef struct snap_metadata_s snap_metadata_t;


#ifndef _WRAP_PRELOAD_H
/* Function prototypes */

void                                objsnf_print_inst_at                    (void * addr);
int                                 objsnf_init_tracer                      ();
size_t                              objsnf_x86_insn_len                     (const unsigned char *code);
void                                objsnf_replace_signal_handler           ();
void                                objsnf_handle_interrupt                 (int signum, siginfo_t *info, void *ctx);
int                                 objsnf_lock_all_objects                 ();
int                                 objsnf_unlock_all_objects               ();
int                                 objsnf_add_interrupt_context            (
                                        pid_t thread_id,
                                        void * orig_addr,
                                        unsigned char orig_instruction,
                                        objsnf_traced_objects_s *object,
                                        interrupt_contexts_s *interrupt_ctx,
                                        bool is_obj_traced /* Usually true, unless we hit a address that incidentally falls on the same page as a traced object */
                                    );
int                                 objsnf_remove_interrupt_context         (unsigned short idx, interrupt_contexts_s *interrupt_ctx);
int                                 objsnf_thread_has_interrupt_contexts    (pid_t thread_id , interrupt_contexts_s *interrupt_ctx);
objsnf_traced_objects_s*            objsnf_address_in_traced_objects        (void *addr, objsnf_traced_objects_s *traced_objects);
void                                objsnf_atexit                           ();

static inline uint64_t              get_gpr64                               (const ucontext_t *uc, unsigned cs_reg);
static inline uint64_t              narrow_to_size                          (uint64_t v, unsigned width_bytes, unsigned high8);
static int                          get_src_scalar                          (const cs_insn *insn, const ucontext_t *uc, uint64_t *out, unsigned *width);
static uint64_t                     apply_rmw                               (uint64_t oldv, uint64_t src, unsigned width, unsigned insn_id);
store_value_t                       compute_store_value                     (const uint8_t *ip, const void *ea, const ucontext_t *uc);

#endif // _WRAP_PRELOAD_H

// This struct is used to store global tracer variables
// Have pages around it to prevent them from locking accidentally
// TODO: This can be improve to only use a single page (given that its initialized at a page boundary)
typedef struct objsnf_safe_globals_s {
    char                       __guard_page[PAGE_SIZE]; // Guard page
    int                        traced_obj_ctr;
    uint64_t                   log_number_counter; // Use to organize snapshots chronologically
    short                      tracer_initialised; // Flag to check if the tracer is initialized
    short                      tracer_cleanup_done; // Flag to check if the tracer cleanup is done
    int                        session_id; // Session ID for the tracer
    interrupt_contexts_s       interrupt_contexts [MAX_INTERRUPT_CONTEXTS];
    objsnf_traced_objects_s    traced_objects  [MAX_OBJ_COUNT];
    #if OBJSNF_ENABLE_SNAPSHOT_BATCHING
    snap_metadata_t            snapshot_metadata_arr[MAX_OBJ_COUNT+1][OBJSNF_MAX_SNAPSHOTS_PER_OBJECT+1]; // Array to hold the heads of the snapshot metadata list for each object
    #endif
    
    struct timespec            init_time;
    char                       __guard_page2[PAGE_SIZE]; // Guard page
} objsnf_safe_globals_t;

#endif // _OBJSNF_SRC

