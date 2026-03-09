#define _OBJSNF_SRC
#include "tracer.h"
#include <errno.h>
#include <dlfcn.h>

extern void*        (*wrapper_objsnf_real_malloc)         (size_t)                  ;

volatile int objsnf_enabled_binary_version = 6; // Flag to check if the binary is enabled for ObjSniff tracing
char __tracer__version__[] = "0.2";

OBJSNF_PG_ALIGN objsnf_safe_globals_t objsnf_gvars = {
    .__guard_page = {0},            // Initialize the guard page
    .traced_obj_ctr = 0,            // Initialize the traced object counter
    .log_number_counter = 0,        // To keep a chronologically ordered log
    .tracer_initialised = 0,        // Initialize the tracer
    .tracer_cleanup_done = 1,       // Initialize the cleanup done flag
    .session_id = 0,                // Initialize the session ID
    .interrupt_contexts = {{0}},       // Initialize the interrupt contexts array
    .traced_objects = {{0}},           // Initialize the traced objects array

    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    .pkey = -1,                       // Initialize the protection key
    #endif

    #if OBJSNF_ENABLE_SNAPSHOT_BATCHING
    .snapshot_metadata_arr = {{{0}}},    // Initialize the snapshot array
    #endif

    .init_time = {0},               // Initialize the init time
    .__guard_page2 = {0}            // Initialize the guard page
};

// Helper callback for dl_iterate_phdr to find the main exe's base address
static int objsnf_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    // Check if the name is empty
    if (size < sizeof(struct dl_phdr_info)) return 0; // continue iteration
    if (!info->dlpi_name || !*info->dlpi_name) {
        *(uintptr_t *)data = info->dlpi_addr; 
        return 1; // stop iteration
    }
    return 0; 
}

void objsnf_export_function_symbols_csv(void) {
    return;
    #if !ENABLE_LOGGING
    return;
    #endif

    // 0) Initialize libelf
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf init failed\n");
        return;
    }

    // 1) Determine if our main exe is PIE
    uintptr_t base_addr = 0;
    dl_iterate_phdr(objsnf_phdr_cb, &base_addr);

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/self/exe");
        return;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin: %s\n", elf_errmsg(-1));
        close(fd);
        return;
    }

    // 3) We look for .symtab first, else .dynsym
    Elf_Scn *scn = NULL, *symtab_scn = NULL;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "elf_getshdrstrndx: %s\n", elf_errmsg(-1));
        goto cleanup;
    }

    // search for .symtab
    while ((scn = elf_nextscn(elf, scn))) {
        GElf_Shdr shdr_mem;
        GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
        if (!shdr) continue;
        const char *secname = elf_strptr(elf, shstrndx, shdr->sh_name);
        if (secname && !strcmp(secname, ".symtab")) {
            symtab_scn = scn;
            break;
        }
    }

    // if .symtab not found, attempt .dynsym
    if (!symtab_scn) {
        scn = NULL;
        while ((scn = elf_nextscn(elf, scn))) {
            GElf_Shdr shdr_mem;
            GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
            if (!shdr) continue;
            const char *secname = elf_strptr(elf, shstrndx, shdr->sh_name);
            if (secname && !strcmp(secname, ".dynsym")) {
                symtab_scn = scn;
                break;
            }
        }
    }

    if (!symtab_scn) {
        fprintf(stderr, "No .symtab or .dynsym found; possibly stripped binary\n");
        goto cleanup;
    }

    // 4) Retrieve symbol table data
    GElf_Shdr symtab_sh;
    if (!gelf_getshdr(symtab_scn, &symtab_sh)) {
        fprintf(stderr, "gelf_getshdr error\n");
        goto cleanup;
    }

    Elf_Data *sym_data = elf_getdata(symtab_scn, NULL);
    if (!sym_data) {
        fprintf(stderr, "elf_getdata sym_data error\n");
        goto cleanup;
    }

    // string table for these symbols
    Elf_Scn *str_scn = elf_getscn(elf, symtab_sh.sh_link);
    if (!str_scn) {
        fprintf(stderr, "elf_getscn for string table error\n");
        goto cleanup;
    }
    Elf_Data *str_data = elf_getdata(str_scn, NULL);
    if (!str_data) {
        fprintf(stderr, "elf_getdata str_data error\n");
        goto cleanup;
    }

    char filename[300];
    sprintf(filename, "objsnf_snapshots/map@[session:%d].csv", objsnf_gvars.session_id);
    FILE * map_fd = fopen(filename, "w");
    if (!fd) {
        fprintf(stderr, "fopen error\n");
        goto cleanup;
    }

    fprintf(map_fd, "start_addr, end_addr, function name\n");

    // 5) Iterate over all symbols
    size_t count = symtab_sh.sh_size / symtab_sh.sh_entsize;
    for (size_t i = 0; i < count; i++) {
        GElf_Sym sym;
        if (!gelf_getsym(sym_data, i, &sym)) continue;

        // We only want STT_FUNC
        if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0) {
            continue;
        }
        // symbol name
        const char *name = NULL;
        if (sym.st_name < str_data->d_size) {
            name = (const char*)str_data->d_buf + sym.st_name;
        }
        if (!name || !*name) {
            continue;
        }

        // compute runtime addresses
        unsigned long start = base_addr + sym.st_value; 
        unsigned long end   = start + sym.st_size; // st_size can be zero
        // print CSV: exe_path,0xstart,0xend,FuncName
        fprintf(map_fd,"0x%lx,0x%lx,%s\n", start, end, name);
    }

    // TODO: Grab all the library calls as well


cleanup:
    elf_end(elf);
    close(fd);
}

/*
    * This function uses the Capstone disassembly framework to decode
    * the instruction at the given address. It returns the length of the
    * instruction in bytes.
    *
    * The function takes a pointer to the instruction code as input and
    * returns the length of the instruction in bytes.
*/
size_t objsnf_x86_insn_len_fast(const uint8_t *addr) {
    static __thread csh insn_length_finder_handle = 0;
    static __thread cs_insn insn_len_finder_insn;

    if (insn_length_finder_handle == 0) {
        cs_opt_mem setup;
        setup.malloc = wrapper_objsnf_zalloc_internal;
        setup.calloc = wrapper_objsnf_zalloc_calloc_internal;
        setup.realloc = wrapper_objsnf_zalloc_realloc_internal;
        setup.free = wrapper_objsnf_zalloc_free_internal;
        setup.vsnprintf = vsnprintf;

        // Finally, setup our own dynamic memory functions with cs_option().
        if (!cs_option(insn_length_finder_handle, CS_OPT_MEM, (size_t) &setup)) { // Some how this means success 
        } else {
            // Failed to initialize our user-defined dynamic mem functions.
            // Quit is the only choice here :-(
            cs_close(&insn_length_finder_handle);
            WRITE_STR_LIT(RED "Error: " RESET "ObjSniff tracer: Failed to set Capstone dynamic memory functions\n");
            exit(1);
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &insn_length_finder_handle) != CS_ERR_OK) return 0;
        cs_option(insn_length_finder_handle, CS_OPT_DETAIL, CS_OPT_OFF);   // speed: no extra detail
    }

    const uint8_t *p = addr;
    size_t bytes_left = 15;        // x86 max
    uint64_t address = 0;          // we don't care about runtime address

    if (cs_disasm_iter(insn_length_finder_handle, &p, &bytes_left, &address, &insn_len_finder_insn))
        return insn_len_finder_insn.size;
    return 0;
}

/*
 * Print the instruction at the given address
 * This is done using the Capstone disassembly framework
 * The instruction is printed in a human readable format
 *
 */
void objsnf_print_inst_at(void * addr) {
    // Print the size of the instruction
    size_t instruction_len = objsnf_x86_insn_len_fast(addr);
    // Decode and print the instruction and print what it is on console
    csh handle = 0;
    cs_insn *insn;
    size_t count;

    cs_opt_mem setup;
    setup.malloc = wrapper_objsnf_zalloc_internal;
    setup.calloc = wrapper_objsnf_zalloc_calloc_internal;
    setup.realloc = wrapper_objsnf_zalloc_realloc_internal;
    setup.free = wrapper_objsnf_zalloc_free_internal;
    setup.vsnprintf = vsnprintf;

    // Finally, setup our own dynamic memory functions with cs_option().
    if (!cs_option(handle, CS_OPT_MEM, (size_t) &setup)) { // Some how this means success 
    } else {
        // Failed to initialize our user-defined dynamic mem functions.
        // Quit is the only choice here :-(
        cs_close(&handle);
        WRITE_STR_LIT(RED "Error: " RESET "ObjSniff tracer: Failed to set Capstone dynamic memory functions\n");
        exit(1);
    }
    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Failed to initialize Capstone\n");
        return;
    }

    // Disassemble *one* instruction from 'addr'
    count = cs_disasm(handle, addr, instruction_len, /*starting address*/ 0, /*num instructions*/ 1, &insn);
    if (count > 0) {
        // Print the Capstone-disassembled instruction
        fprintf(stderr, "Instruction @%p[ %zubytes ]:  %s %s\n\n", (void*) addr , instruction_len ,  insn[0].mnemonic, insn[0].op_str);

        // Free the Capstone array
        cs_free(insn, count);
    } else {
        fprintf(stderr, "ERROR: Failed to disassemble instruction\n");
    }

    // Close Capstone handle
    cs_close(&handle);

}

/*
    * Replace the signal handler for SIGSEGV and SIGTRAP
    * This is done so that we can catch the signals and handle them
    * ourselves. This is done using the sigaction system call.
    * The signal handler is replaced with the handle_interrupt function
*/
void objsnf_replace_signal_handler() {
    
    // Change the current signal handler to the new one
    // sigaction(SIGINT, &objsnf_newSigHandler, NULL);
    // sigaction(SIGSEGV, &objsnf_newSigHandler, NULL);
    // sigaction(SIGTRAP, &objsnf_newSigHandler, NULL);
    struct sigaction sa;
    sa.sa_sigaction = objsnf_handle_interrupt;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;  // Enable extended signal info

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);

    #if OBJSNF_ENABLE_SNAPSHOT_BATCHING
    // TODO: More testing need to ensure that this works correctly
    // Register the at_exit handler to clean up on exit
    struct sigaction at_exit_sa;
    at_exit_sa.sa_handler = objsnf_atexit;
    sigemptyset(&at_exit_sa.sa_mask);
    at_exit_sa.sa_flags = 0; // No special flags
    sigaction(SIGINT, &at_exit_sa, NULL); // Register the at_exit handler for SIGINT
    sigaction(SIGTERM, &at_exit_sa, NULL); // Register the at_exit handler for SIGTERM
    sigaction(SIGQUIT, &at_exit_sa, NULL); // Register the at_exit handler for SIGQUIT
    sigaction(SIGABRT, &at_exit_sa, NULL); // Register the at_exit handler for SIGABRT
    sigaction(SIGFPE, &at_exit_sa, NULL); // Register the at_exit handler for SIGFPE
    atexit(objsnf_atexit); // Register the atexit handler to clean up on exit

    #if PRINT_STATE_INFO
    printf( "\n" TRACER_PRMPT " Signal handlers replaced for SIGSEGV and SIGTRAP\n");
    #endif

    #endif
}

void ichnaea_hexdump( void * ptr, size_t buflen ) {
    unsigned char *buf = (unsigned char*)ptr;
    char buffer[80];
    // Use WRITE_STR_LIT to print the hexdump
    for (size_t i = 0; i < buflen; i += 16) {
        size_t line_len = snprintf(buffer, sizeof(buffer), "%06zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < buflen) {
                line_len += snprintf(buffer + line_len, sizeof(buffer) - line_len, "%02x ", buf[i + j]);
            } else {
                line_len += snprintf(buffer + line_len, sizeof(buffer) - line_len, "   ");
            }
        }
        line_len += snprintf(buffer + line_len, sizeof(buffer) - line_len, " ");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < buflen) {
                char c = buf[i + j];
                line_len += snprintf(buffer + line_len, sizeof(buffer) - line_len, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        line_len += snprintf(buffer + line_len, sizeof(buffer) - line_len, "\n");
        WRITE_STR_LIT(buffer);
    }
}

void objsnf_atexit() {
    #if PRINT_STATE_INFO
    WRITE_STR_LIT("\n" TRACER_PRMPT GREEN "ObjSniff tracer: atexit called, cleaning up...\n" RESET);
    #endif
    #if !ENABLE_LOGGING
    return;
    #endif
    
    #if OBJSNF_ENABLE_SNAPSHOT_BATCHING

    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    // Unlock the pkey to allow writing to everything
    if ( pkey_set(objsnf_gvars.pkey , 0x0)
        == -1 ) {
        perror("pkey_set@" AT_LINE);
        return;
    }
    #endif

    if (ichnaea_state == EXITING) {
        printf("\n" TRACER_PRMPT "ObjSniff tracer: Cleanup already done, exiting...\n");
        exit(0);
    } else ichnaea_state = EXITING;

    // Create the output directory if it doesn't exist
    struct stat st = {0};
    if (stat("objsnf_snapshots", &st) == -1) {
        mkdir("objsnf_snapshots", 0700);
    }


    // Malloc a big chunk of memory to hold the metadata
    char *metadata_txt_buffer = wrapper_objsnf_zalloc_internal(MAX_METADATA_BUFFER_SIZE);

    for (int index_of_object = 0; index_of_object < MAX_OBJ_COUNT; index_of_object++) {

        objsnf_traced_objects_s *obj = &objsnf_gvars.traced_objects[index_of_object];
        
        if (obj->addr == NULL) break; // No more traced objects
        

        #if PRINT_STATE_INFO
            printf( TRACER_PRMPT "\n\nWriting metadata for object %s with snap_count %d i is: %d\n", obj->name, obj->snap_count, index_of_object);
        #endif

        #if !OBJSNF_ENABLE_PKEY_BASED_LOCK
        // Make the pages writable (Do we really need this??)
        if (mprotect(obj->addr, obj->size, PROT_READ | PROT_WRITE) == -1) {
            printf(RED "Error: " RESET "ObjSniff tracer: Failed to make object %s writable: %s\n", obj->name, strerror(errno));
            continue; // Skip this object if we can't make it writable
        }
        #endif

        // JSON Initial brace
        snprintf(metadata_txt_buffer, MAX_METADATA_BUFFER_SIZE , "{\n");

        // Write the object metadata
        snprintf(
            metadata_txt_buffer + strlen(metadata_txt_buffer),
            MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
            "  \"object\": {\n"
            "    \"addr\": \"%p\",\n"
            "    \"size\": %ld,\n"
            "    \"name\": \"%s\",\n"
            "    \"type\": \"%s\",\n"
            "    \"snap_count\": %d,\n"
            "    \"registration_cs_size\": %d,\n"
            "    \"registration_call_stack\": ["
            ,
            obj->unaligned_addr,
            obj->unaligned_size,
            obj->name,
            obj->type,
            obj->snap_count,
            obj->call_stack_size
        );

        // Write the call stack strings of the registration site (returned by backtrace symbols) to buffer
        for (int j = 1; j < obj->call_stack_size; j++) {
            snprintf(
                metadata_txt_buffer + strlen(metadata_txt_buffer),
                MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
                "\n\t\t\t\t\t\"%s\"%s",
                obj->call_stack[j],
                (j == obj->call_stack_size - 1 ? "\n" : ", ")
            );
        }

        snprintf(
            metadata_txt_buffer + strlen(metadata_txt_buffer),
            MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
            "\t\t]\n\t},\n"
        );

        // Write the snapshots metadata
        for (int snap_idx = 0; snap_idx < obj->snap_count; snap_idx++) {
            
            snap_metadata_t * snapshot_addr = &objsnf_gvars.snapshot_metadata_arr[index_of_object][snap_idx];

            // Write the metadata to buffer
            snprintf(
                metadata_txt_buffer + strlen(metadata_txt_buffer),
                MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
                "  \"snapshot_%d\": {\n"
                "    \"hash\": \"%llu\",\n"
                "    \"call_stack_size\": %d,\n"
                "    \"is_syscall_dump\": %s,\n"
                "    \"is_read\": %s,\n"
                "    \"call_stack\": [",
                snap_idx,
                snapshot_addr->hash,
                snapshot_addr->call_stack_size,
                (snapshot_addr->is_syscall_dump ? "true" : "false"),
                (snapshot_addr->is_read ? "true" : "false")
            );
            
            if (snapshot_addr->call_stack_size) {
                // Write the snap call stack to buffer
                // TODO: These calls are expensive and this should be resolved in the future
                // Ideally i'd post process all this but I don't have the time to do all that so we pay the pferformance cost here
                // If i get time later, i'll optimize this
                // also, the reson I'm calling it here is because i don't wanna call this expensive function the the interrupt handler
                char ** symbol_buffer = backtrace_symbols(
                    snapshot_addr->call_stack,
                    snapshot_addr->call_stack_size
                );

                // Write the snap call stack strings to buffer
                for (int k = 0; k < snapshot_addr->call_stack_size; k++) {
                    snprintf(
                        metadata_txt_buffer + strlen(metadata_txt_buffer),
                        MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
                        "\n\t\t\t\t\t\"%s\"%s",
                        symbol_buffer[k],
                        (k == snapshot_addr->call_stack_size - 1 ? "\n" : ", ")
                    );
                }
                // free(symbol_buffer); // Dont waste time by freeing since we're exiting anyways? 
            }

            snprintf(
                metadata_txt_buffer + strlen(metadata_txt_buffer),
                MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
                "\t\t],\n"
                "    \"pid\": %d,\n"
                "    \"tid\": %d\n"
                "  }%s\n",
                snapshot_addr->pid,
                snapshot_addr->tid,
                (snap_idx == obj->snap_count - 1 ? "" : ",")
            );
        }

        snprintf(
            metadata_txt_buffer + strlen(metadata_txt_buffer),
            MAX_METADATA_BUFFER_SIZE  - strlen(metadata_txt_buffer),
            "}\n"
        );

        // Write the metadata to a file

        char filename[300];
        snprintf(
            filename, sizeof(filename),
            "objsnf_snapshots/metadata@[session:%d][name:%s][size:%ld][%s].json",
            objsnf_gvars.session_id,
            obj->name,
            obj->unaligned_size,
            (obj->is_un_aligned ? "unaligned" : "aligned")
        );
        FILE *fp = fopen(filename, "w");
        if (fp) {
            fwrite(metadata_txt_buffer, strlen(metadata_txt_buffer), 1, fp);
            fclose(fp);
        } else {
            printf(RED "Error: " RESET "ObjSniff tracer: Failed to write metadata to file %s\n", filename);
            // Print the error
            perror("fopen@" AT_LINE);
        }
        #if PRINT_STATE_INFO
        printf(TRACER_PRMPT "Wrote metadata for object %s to file %s\n", obj->name, filename);
        #endif

        // Write the snapshot buffer to a file
        char snap_filename[300];
        snprintf(
            snap_filename, sizeof(snap_filename),
            "objsnf_snapshots/bin_data@[session:%d][name:%s][size:%ld][%s].bin",
            objsnf_gvars.session_id,
            obj->name,
            obj->unaligned_size,
            (obj->is_un_aligned ? "unaligned" : "aligned")
        );
        FILE *snap_fp = fopen(snap_filename, "wb");
        if (snap_fp) {
            // Write the snapshot buffer to the file
            fwrite(
                objsnf_gvars.snapshot_metadata_arr[index_of_object][0].snap_buffer,
                obj->unaligned_size * obj->snap_count,
                1,
                snap_fp
            );
            fclose(snap_fp);
            #if PRINT_STATE_INFO
            printf(TRACER_PRMPT "Wrote snapshot buffer for object %s to file %s\n", obj->name, snap_filename);
            #endif
        }
    }
                
                


    #if PRINT_STATE_INFO
    printf("\n" TRACER_PRMPT BLUE "ObjSniff tracer: End of Exit, Bye!\n" RESET);
    #endif
    
    exit(0);

    #else
    return;
    #endif
}

static inline char *itoa_u64(char *buf_end, uint64_t v)
{
    char *p = buf_end;
    *--p = '\0';   // Null terminator (not required for write(), but neat)

    if (v == 0) {
        *--p = '0';
        return p;
    }

    while (v > 0) {
        *--p = '0' + (v % 10);
        v /= 10;
    }

    return p;
}

static inline void tracer_log_snapshot(unsigned long snapnum)
{
    char buf[128];
    char *p = buf;

    // Fixed prefix
    const char prefix[] = "Tracer: Taking snapshot number: ";
    const size_t prefix_len = sizeof(prefix) - 1;

    // Copy prefix manually (no memcpy)
    for (size_t i = 0; i < prefix_len; i++)
        *p++ = prefix[i];

    // Convert integer
    char *num_start = itoa_u64(p + 32, snapnum);   // safe room
    // Copy digits into buffer
    while (*num_start)
        *p++ = *num_start++;

    // Append newline
    *p++ = '\n';

    // // Write to stderr (async-signal-safe)
    // write(STDERR_FILENO, buf, p - buf);
    WRITE_STR_LIT(buf);
}


__attribute__((noinline, optimize("O0")))
void *ichnaea_memcpy(void *dst, const void *src, size_t n)
{
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const volatile unsigned char *s = (const volatile unsigned char *)src;

    for (size_t i = 0; i < n; i++)
        d[i] = s[i];

    return dst;
}

// Interrupt signal handler
void objsnf_handle_interrupt(int signum, siginfo_t *info, void *ctx) {
    
    ucontext_t *uc = (ucontext_t *)ctx;

    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    // Unlock everything right away
    if ( pkey_set(objsnf_gvars.pkey , 0x0) == -1 ) {
        perror("pkey_set@" AT_LINE);
        return;
    }
    #endif
    
    // Find the instruction addr that caused the segfault
    void * addr;
    
    #if defined(__x86_64__)
    // On x86_64, the saved instruction pointer is in gregs[REG_RIP]
    // You can also adjust RSP, RBP, registers, flags, etc.
    addr = (void *) uc->uc_mcontext.gregs[REG_RIP];// = (uintptr_t)some_alternate_function;

    #elif defined(__i386__)
    // On 32-bit x86, the saved EIP is in gregs[REG_EIP]
    addr = uc->uc_mcontext.gregs[REG_EIP] = (uintptr_t)some_alternate_function;
    #else
    #   error "Not implemented for this architecture."
    #endif


    // Check if there is a context for this thread
    pid_t thread_id = gettid(); // Maybe replace this with a thread local ID so that we don't have to call gettid() every time
    int ctx_idx = objsnf_thread_has_interrupt_contexts(thread_id, objsnf_gvars.interrupt_contexts);

    #if PRINT_STATE_INFO
        if (ctx_idx == -1) WRITE_STR_LIT(RED"\n>--------------------\n" RESET); // The arrows indicate start of a new interrupt handling session
    #endif
    

    DISABLE_SMART_ALLOC(); // Lock the smart allocators (wrappers) so mallocs are servered from the real malloc

    // ichnaea_smart_alloc_lock = 1;
    
    // Write the address of ichnaea_smart_alloc_lock to stdout for debugging

    if (signum == SIGTRAP) {

        // If it's a trap without a context, then we ignore it
        if (ctx_idx == -1) {
            WRITE_STR_LIT(YELLOW "YELLOW\n");
            printf( YELLOW "Warning:" RESET "A trap signal was called. This tracer can't work if your application uses traps and trap handlers!!\n");
            ENABLE_SMART_ALLOC();
            // TODO: This should kill the program as it is a genuine trap
            return;
        }
        
        // Lets unlock reading so that the instruction can read the object
        
        // Set the pkey to enable read only access
        if ( pkey_set(objsnf_gvars.pkey ,0x0)
            == -1 ) {
            perror("pkey_set@" AT_LINE);
            exit(1);
        }

        // if ( pkey_mprotect(objsnf_gvars.interrupt_contexts[ctx_idx].object->addr, objsnf_gvars.interrupt_contexts[ctx_idx].object->size, PROT_READ | PROT_WRITE, 0) == -1 ) {
        //     perror("pkey_mprotect@" AT_LINE);
        //     exit(1);
        // }
        


        // objsnf_gvars.interrupt_contexts[ctx_idx].object->snap_count += 1;


        #if ENABLE_LOGGING
            if (objsnf_gvars.interrupt_contexts[ctx_idx].is_obj_traced) {
                objsnf_log_event(
                    objsnf_gvars.interrupt_contexts[ctx_idx].object,
                    false,
                    objsnf_gvars.interrupt_contexts[ctx_idx].is_read,
                    uc
                );
            }
        #endif
        

        #if PRINT_STATE_INFO
        WRITE_STR_LIT( TRACER_PRMPT "Relocking the Object\n");
        #endif

        #if !OBJSNF_ENABLE_PKEY_BASED_LOCK
        // Relock the object
        if (mprotect(objsnf_gvars.interrupt_contexts[ctx_idx].object->addr, objsnf_gvars.interrupt_contexts[ctx_idx].object->size , PROT_READ) == -1) {
            perror("mprotect@" AT_LINE );
            exit(1);
        }
        #else
        
        // Set the pkey for the object's page to the allocated pkey
        if ( pkey_mprotect(objsnf_gvars.interrupt_contexts[ctx_idx].object->addr, objsnf_gvars.interrupt_contexts[ctx_idx].object->size, PROT_READ | PROT_WRITE, objsnf_gvars.pkey) == -1 ) {
            perror("pkey_mprotect@" AT_LINE);
            exit(1);
        }

        // Set the pkey to enable read only access
        if ( pkey_set(objsnf_gvars.pkey , ICHNAEA_TRACE_READS ? PKEY_DISABLE_ACCESS : PKEY_DISABLE_WRITE)
            == -1 ) {
            perror("pkey_set@" AT_LINE);
            exit(1);
        }
        
        #endif
        
        
        // Restore the original instruction
        *( (char *) objsnf_gvars.interrupt_contexts[ctx_idx].orig_addr) = objsnf_gvars.interrupt_contexts[ctx_idx].orig_instruction; // Restore the original instruction
        
        // Reset the IP
        uc->uc_mcontext.gregs[REG_RIP] = (greg_t)objsnf_gvars.interrupt_contexts[ctx_idx].orig_addr;
        


        objsnf_remove_interrupt_context(ctx_idx, objsnf_gvars.interrupt_contexts);

        ENABLE_SMART_ALLOC(); // Unlock the smart malloc
        
        #if PRINT_STATE_INFO
        WRITE_STR_LIT(RED "--------------------\n\n" RESET);
        #endif
        


        return;
    }

    else if (signum == SIGSEGV) {
        
        // Find the memory address that was accessed
        void * obj_addr = info->si_addr;

        bool segfault_caused_by_read = ((uc->uc_mcontext.gregs[REG_ERR] & 0x2) == 0);

        
        
        // TODO: This method should check if the object is in the same page as well, two calls are completly unnessary
        objsnf_traced_objects_s * obj_node = objsnf_address_in_traced_objects(obj_addr, objsnf_gvars.traced_objects);
        bool is_object_traced = true;

        if (obj_node == NULL) { // Obj node being null means that the address is not in the traced objects
            // Check if it falls in the same page
            obj_node = objsnf_address_within_traced_objects_pg(obj_addr, objsnf_gvars.traced_objects);
            if (obj_node == NULL) {
                printf(RED "Error: A actual segmentation fault occured, exiting\n" RESET);
                exit(0);
            }
            else {
                #if ENABLE_WARNINGS

                char buffer_warn[300];
                memset(buffer_warn, 0, sizeof(buffer_warn));
                snprintf(buffer_warn, sizeof(buffer_warn), TRACER_PRMPT YELLOW "Warning: " RESET "Segfault address %p is not within the traced object %s at %p\n", info->si_addr, obj_node->name, obj_node->addr);
                WRITE_STR_LIT(buffer_warn);
                fflush(stdout);

                #endif
                is_object_traced = false;
            }
        }
        
        // TODO: More engineering effort is required for SIMD and FPU MOVES right now it falls back to adding a break point and letting the instruction run natively
        store_value_t k = compute_store_value(addr, obj_addr , uc);

        #if PRINT_STATE_INFO
        #if ENABLE_DLINFO
        Dl_info dl_info;
        if (dladdr(addr, &dl_info)) {
            // Find the offset into the function
            printf( TRACER_PRMPT 
                RED "Segfault" RESET " @ Instruction: %p (%s+%p), obj addr %p\n",
                addr, dl_info.dli_sname, (void *)((uintptr_t)addr - (uintptr_t)dl_info.dli_saddr), info->si_addr
            );fflush(stdout);
        }
        #else
        char _buffbuf[500];
        // printf( RED "Segfault" RESET " @ Instruction: %p (obj addr: %p, tid: %d)\n\n", addr, info->si_addr, thread_id);fflush(stdout);
        memset(_buffbuf, 0, sizeof(_buffbuf));
        
        snprintf(_buffbuf,
            sizeof(_buffbuf),
            TRACER_PRMPT RED "%s Segfault" RESET " @ Instruction: %p (obj addr: %p, tid: %d)\n\n",
            (segfault_caused_by_read ? "Read" : "Write"),
            addr,
            info->si_addr,
            thread_id
        );
        WRITE_STR_LIT(_buffbuf);
        #endif
        #endif  

        
        if (k.ok) { // If we can decode the instruction then lets decode it

            #if PRINT_STATE_INFO
            WRITE_STR_LIT( "Emulation successful\n");
            #endif
            // Unlock the object
            // If pkey based locking is disabled, then we use mprotect
            #if !OBJSNF_ENABLE_PKEY_BASED_LOCK
            if (mprotect( obj_node->addr , obj_node->size , PROT_READ | PROT_WRITE) == -1) {
                perror("mprotect@" AT_LINE );
                return;
            }
            #else
            // Set the pkey for the object's page to the allocated pkey
            if ( pkey_set(objsnf_gvars.pkey , 0x0) == -1 ) {
                perror("pkey_set@" AT_LINE);
                return;
            }
            #endif

            uint8_t tmp[8];
            // Copy LSBs into tmp (compile-time intrinsic on -O2+)
            ichnaea_memcpy(tmp, &k.value, sizeof(tmp));     // copies 8 bytes to tmp
            // Store only 'width' bytes to the target address
            ichnaea_memcpy(obj_addr , tmp, k.width);

            // Relocking is needed here for mprotect based locking
            // Incase of pkey based locking, they keys are restored
            // to the original state at interrupt handler exit
            #if !OBJSNF_ENABLE_PKEY_BASED_LOCK
            if (mprotect( obj_node->addr , obj_node->size , PROT_READ) == -1) {
                perror("mprotect@" AT_LINE );
                return;
            }
            #endif
            
            // Find the size of the instrn size
            int size = objsnf_x86_insn_len_fast(addr);

            // Find the address of the next instruction
            void *nxt_inst = (void *)((uintptr_t)addr + (uintptr_t)size);

            // Skip to the next instruction as we have emulated this one 
            uc->uc_mcontext.gregs[REG_RIP] = (greg_t)nxt_inst;
            
            if (is_object_traced) objsnf_log_event(obj_node, false, segfault_caused_by_read, uc);

            ENABLE_SMART_ALLOC();

            #if PRINT_STATE_INFO
            WRITE_STR_LIT(RED"--------------------\n" RESET);
            #endif

            return;
        } else {
            #if PRINT_STATE_INFO
            WRITE_STR_LIT("Emulation failed, falling back to breakpoint method\n");
            #endif
        }

        if (ctx_idx == -1) {
            // If there is no context, then we need to create one
            obj_addr = (void *) ( (uintptr_t)addr & ~(PAGE_SIZE - 1));
            ctx_idx = objsnf_add_interrupt_context(
                thread_id,
                addr,
                '\0',
                obj_node,
                objsnf_gvars.interrupt_contexts,
                is_object_traced,
                segfault_caused_by_read
            );
            

            if (ctx_idx == -1) {WRITE_STR_LIT("Failed to add interrupt context\n");return;}
        }
        else {
            ichnaea_boxed_print(RED "Error: A segfault fault happened while handling a segfault, exiting" RESET);
            exit(0);
        }

        
        

        /* ADDING A BREAKPOINT */

        // Make memory at addr (.text) writeable 
        void * aligned_addr_of_instruction = (void *) ( (uintptr_t)addr & ~(PAGE_SIZE - 1));

        if (mprotect(aligned_addr_of_instruction, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) perror("mprotect@" AT_LINE);

        size_t _len_of_this_instruction = objsnf_x86_insn_len_fast(addr);
        void * nxt_inst = (void *) ( ((uintptr_t)addr) + (uintptr_t)(_len_of_this_instruction) );
        
        // Save the first byte at the address by copying it to orig_instruction field of the context
        objsnf_gvars.interrupt_contexts[ctx_idx].orig_instruction = *(unsigned char *)nxt_inst;
        objsnf_gvars.interrupt_contexts[ctx_idx].orig_addr = nxt_inst;
        
        * ((unsigned char *)nxt_inst) = 0xccLU; // INT3
        
        #if !OBJSNF_ENABLE_PKEY_BASED_LOCK
        // Unlock the object
        if (mprotect(obj_node->addr, obj_node->size , PROT_READ | PROT_WRITE) == -1) {
            perror("mprotect6" AT_LINE);
            return;
        }
        #else
        // Set the pkey for the object's page to the default key.
        // This will leave the object exposed for a short time however,
        // this is only the case where we can't emulate the instruction 
        // which won't be a problem when we improve the instruction emulation
        if ( pkey_mprotect(obj_node->addr, obj_node->size, PROT_READ | PROT_WRITE, 0) == -1 ) {
            perror("pkey_mprotect@" AT_LINE);
            return;
        }
        #endif
        
        // ENABLE_SMART_ALLOC(); // Unlock the smart malloc
        
        return;
    }

    else {
        printf("No context found for received signal %d, Faulting Address: %p\n Exiting\n" , signum, info->si_addr);
        exit(0);
    }
}

// Logs the event to a file
// @param obj The object to log
// @param syscall_dump If true, then it means that this might not reflect a change in the object but rather
//                     that the object was logged incase it had been modified by a syscall
// TODO:
// Improve this method by a lot
// It sucks rn
int objsnf_log_event(objsnf_traced_objects_s *obj, bool syscall_dump, bool is_read, ucontext_t * vctx) {

    #if ENABLE_LOGGING

    if (obj->snap_count >= OBJSNF_MAX_SNAPSHOTS_PER_OBJECT) {
        #if !DISABLE_CRITICAL_LOGGING
        WRITE_STR_LIT(YELLOW "Warning: " RESET "ObjSniff tracer: Maximum num of snapshots (" STRINGIZE(OBJSNF_MAX_SNAPSHOTS_PER_OBJECT) ") reached for object ");
        WRITE_STR_LIT(obj->name);
        WRITE_STR_LIT("\n");
        #endif
        return 1;
    }
    if (obj->addr == NULL) {
        #if !DISABLE_CRITICAL_LOGGING
        printf(RED "Error: " RESET "ObjSniff tracer: Object %s is not registered, cannot log event\n", obj->name);
        #endif
        return 1;
    }

    // TODO: check if the hash matches the last snapshot
    snap_metadata_t metadata = {0};
    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    int pkey_status = pkey_get(objsnf_gvars.pkey);
    // Enable reading and writing
    if ( pkey_set(objsnf_gvars.pkey , 0x0)
        == -1 ) {
        perror("pkey_set temporary enable@" AT_LINE);
        return 1;
    }
    #endif

    if (vctx != NULL) {
        unw_cursor_t cursor;
        unw_word_t ip;
        unw_context_t uc;
        unsigned int depth = 0;
        unsigned counter = 0;
        unw_getcontext(&uc); // SIG-Safe

        /* IMPORTANT: we use _local2 with UNW_INIT_SIGNAL_FRAME */
        if (unw_init_local2(&cursor, &uc, UNW_INIT_SIGNAL_FRAME) < 0) { // SIG-Safe
            fprintf(stderr, "Warning: Error initializing unwinding cursor at" AT_LINE "\n");
            return 1;
        }

        while (depth < MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT) {
            if (unw_get_reg(&cursor, UNW_REG_IP, &ip) < 0) break; // SIG-Safe
            if (depth++ > 3) counter++; // Skip first 3 frames (this function and the signal handler and libc)
            metadata.call_stack[counter] = (void *)ip;
            int ret = unw_step(&cursor); // SIG-Safe
            if (ret <= 0) break;
        }
        metadata.call_stack_size = ++counter;
    } else {
        // Since we're not given a context (meaning we're NOT being called from the interrupt handler) we use AS_unsafe backtrace without a care
        metadata.call_stack_size = backtrace(metadata.call_stack, MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT); // Get the call stack pointers
    }

    
    #if !OBJSNF_ENABLE_SNAPSHOT_BATCHING
    char ** bt_syms = backtrace_symbols( metadata.call_stack , metadata.call_stack_size);
    #endif
    metadata.pid = getpid();
    metadata.tid = gettid(); 
    
    #if OBJSNF_ENABLE_SNAPSHOT_BATCHING // If we're using snapshot batching

    // Get the object's index in the snapshot array (no error checking here cause ik it exists)
    // TODO: Refactor code to aleviate the need to search, searching is crazy
    int obj_idx = 0;
    for (; obj_idx < objsnf_gvars.traced_obj_ctr; obj_idx++) {
        if (objsnf_gvars.traced_objects[obj_idx].unaligned_addr == obj->unaligned_addr) break;
    }

    // Calculate the pointer to the correct snapshot location in the buffer
    snap_metadata_t * snapshot_ptr = &objsnf_gvars.snapshot_metadata_arr[obj_idx][obj->snap_count];
    
    // Fill the snapshot metadata
    snapshot_ptr->pid = metadata.pid;
    snapshot_ptr->tid = metadata.tid;
    snapshot_ptr->call_stack_size = metadata.call_stack_size;
    snapshot_ptr->is_read = is_read;
    snapshot_ptr->hash = 0; // TODO: Add hashing
    snapshot_ptr->is_syscall_dump = syscall_dump;

    // Copy the call stack pointers
    int stk_depth = metadata.call_stack_size < MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT ? metadata.call_stack_size : MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT;
    

    for (int i = 0; i < stk_depth; i++) {
        snapshot_ptr->call_stack[i] = metadata.call_stack[i];
    }



    // memcpy(
    //     // TODO: Tripple Check this math at some point
    //     (unsigned char *) snapshot_ptr->snap_buffer + ( obj->snap_count * obj->unaligned_size) ,
    //     obj->unaligned_addr,
    //     obj->unaligned_size
    // );

    ichnaea_memcpy(
        (unsigned char *) snapshot_ptr->snap_buffer + ( obj->snap_count * obj->unaligned_size) ,
        obj->unaligned_addr,
        obj->unaligned_size
    );


    // Restrore pkey status
    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
        if (pkey_status != 0) {
            if ( pkey_set(objsnf_gvars.pkey , pkey_status)
                == -1 ) {
                perror("pkey_set restore status@" AT_LINE);
                return 1;
            }
        }
    #endif

    #else // If we're not using snapshot batching, we need to create a metadata buffer
    
    char call_graph_buffer[4240]; // 10KiB metadata buffer (Basically the legacy/inefficient .cg file)
    
    snprintf(call_graph_buffer, sizeof(call_graph_buffer), "PID: %d, TID: %d\n", metadata.pid, metadata.tid);
    snprintf(call_graph_buffer + strlen(call_graph_buffer), sizeof(call_graph_buffer) , "Object type:%s\n", obj->type);
    
    if (bt_syms != NULL) {
        for (int i = 3; i < metadata.call_stack_size; i++) sprintf(call_graph_buffer + strlen(call_graph_buffer), "%s\n", bt_syms[i]);
        free(bt_syms); // Free the backtrace symbols
    }
    else snprintf(call_graph_buffer + strlen(call_graph_buffer), sizeof(call_graph_buffer), "No backtrace symbols found\n");
    
    // Create the binary snapshot file
    char filename[300];
    snprintf(
        filename, sizeof(filename),
        "objsnf_snapshots/obj@[session:%d][name:%s][size:%ld][snap:%ld][%s]",
        objsnf_gvars.session_id,
        obj->name,
        obj->unaligned_size,
        objsnf_gvars.log_number_counter,
        (syscall_dump ? "syscall" : "normal")
    );

    FILE *fp = fopen(filename, "w");
    if (fp) {
        fwrite(obj->unaligned_addr, obj->unaligned_size, 1, fp);
        fclose(fp);
    }

    // Zero out the filename buffer for cg_filename
    memset(filename,'\0',strlen(filename));

    
    // Create the call graph file
    snprintf(
        filename, sizeof(filename),
        "objsnf_snapshots/obj@[session:%d][name:%s][size:%ld][snap:%ld][%s].cg",
        objsnf_gvars.session_id,
        obj->name,
        obj->unaligned_size,
        objsnf_gvars.log_number_counter,
        (syscall_dump ? "syscall" : "normal")
    );

    FILE *fp2 = fopen(filename, "w");
    if (fp2) {
        fwrite(call_graph_buffer, strlen(call_graph_buffer), 1, fp2); // Write only the valid string length
        fclose(fp2);
    }
    #endif // OBJSNF_ENABLE_SNAPSHOT_BATCHING

    obj->snap_count++;
    objsnf_gvars.log_number_counter++;

    #endif // ENABLE_LOGGING
    
    return 0;
}

// Public API function to register an object for tracing with the new name
int ichnaea_register_object(void *addr, size_t size , char *name , char *type) {
    return objsnf_register_object(addr, size, name, type);
}

int objsnf_register_object(void *addr, size_t size , char *name , char *type) {
    if (!objsnf_gvars.tracer_initialised) objsnf_init_tracer();
    
    // Unlock the pkey to allow writing to everyuthing just to be safe
    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    
    if ( pkey_set(objsnf_gvars.pkey , 0x0) == -1 ) {
        char buffer[300];
        memset(buffer, '\0', sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "Error:"  " Tracer is: %s and the pkey is: %d at line " AT_LINE,
            (objsnf_gvars.tracer_initialised ? "initialised" : "not initialised"),
            objsnf_gvars.pkey
        );
        WRITE_STR_LIT(buffer);
        ENABLE_SMART_ALLOC();
        // TODO: We should exit here
        return 1;
    }
    #endif


    #if PRINT_STATE_INFO
        WRITE_STR_LIT("\n"BLUE ">--------------------\n" RESET);
        WRITE_STR_LIT("\n" TRACER_PRMPT "ObjSniff tracer: Registering object...\n");
    #endif

    // Malloc can now register objects, so while registering objects from inside of wrapped malloc
    // if any other malloc calls are made they'll might call cause a recursive loop of wrapped malloc
    // Adding this lock makes sure that any subsequent malloc calls are served by the real malloc
    DISABLE_SMART_ALLOC(); // Lock the wrapped malloc so it can't be used for any other thread


    // 0x55 is a dummy address simply used to initialize the tracer as the public API doesn't expose an init function
    if (addr == (void *)0x55) {
        ENABLE_SMART_ALLOC();
        return 0;
    }
    bool same_name = false;
    // Check for duplicate names/addresses
    for (int i = 0; i < objsnf_gvars.traced_obj_ctr; i++) {
        if (objsnf_gvars.traced_objects[i].unaligned_addr == addr) {

            if (objsnf_gvars.traced_objects[i].has_been_freed) {
                // If the object has been freed, we can re-register it
                #if (ENABLE_WARNINGS && PRINT_STATE_INFO)
                printf(YELLOW "Warning: " RESET "ObjSniff tracer: Object with address %p was previously freed, re-registering\n", addr);
                #endif
                break;
            }
            else{
                #if (PRINT_STATE_INFO || ENABLE_WARNINGS)
                printf(YELLOW "Warning: " RESET "ObjSniff tracer: Object with address %p already registered\n", addr);
                #endif
                ENABLE_SMART_ALLOC();
                return 1;
            }
        }
        if ( 
            objsnf_gvars.traced_objects[i].name[0] != '\0' &&
            name != NULL &&
            strcmp(objsnf_gvars.traced_objects[i].name, name) == 0
            ) {
            same_name = true;
            #if (PRINT_STATE_INFO || ENABLE_WARNINGS)
            printf(YELLOW "Warning: " RESET "ObjSniff tracer: Object with name %s already registered, appending _%d to the name\n", name, objsnf_gvars.traced_obj_ctr+1);
            #endif
        }
    }

    
    // Check if max object count is reached
    if (objsnf_gvars.traced_obj_ctr >= MAX_OBJ_COUNT) {
        #if PRINT_STATE_INFO
        printf(RED "Error: " RESET "ObjSniff tracer: Maximum object count reached (%d)\n", MAX_OBJ_COUNT);
        #endif
        return 1;
    }

    

    if (!addr || !size) {
        #if !DISABLE_CRITICAL_LOGGING
        printf(RED "Error: " RESET "ObjSniff tracer: Invalid address or size\n");
        #endif
        return 1;
    }

    // We're clear to register the object
    if ( (uintptr_t)addr % PAGE_SIZE == 0) { /* If the address is page aligned */
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].addr = addr;
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].size = size;
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].is_un_aligned = false;
        #if PRINT_STATE_INFO
        char prt_buffer[300];
        memset(prt_buffer, '\0', sizeof(prt_buffer));
        snprintf(prt_buffer, sizeof(prt_buffer), "\n" TRACER_PRMPT "Registering aligned object %s@%p[%ldbytes] tid: %d:", 
            (name ? name : "unnamed"), addr, size, gettid());
        WRITE_STR_LIT(prt_buffer);
        #endif
    } else {  /* If the address isn't page aligned */
        // The MMU can only designate whole pages as read-only, so every address given to mprotect (to make ReadOnly) should be page aligned,
        // Since the object being registered is not aligned to a page size, while calling mprotect we need to align the address
        // to the nearest page size boundary and adjust the size accordingly. This will have a side effect of making everything in the page read-only,
        // but we will log the unaligned address and size so we know if an untraced object was modified.
        void * aligned_addr = (void *) ( (uintptr_t)addr & ~(PAGE_SIZE - 1));
        size_t aligned_size = size + ( (uintptr_t)addr - (uintptr_t)aligned_addr); // Adjust the size by adding the difference between the aligned address and the original address
        
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].is_un_aligned = true;
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].addr = aligned_addr;
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].size = aligned_size;
        #if PRINT_STATE_INFO
        char prt_buffer[300];
        memset(prt_buffer, '\0', sizeof(prt_buffer));
        snprintf(prt_buffer, sizeof(prt_buffer), "\n" TRACER_PRMPT "Registering unaligned object %s@%p[%ldbytes] (aligned to %p[%ldbytes]) tid: %d:", 
            (name ? name : "unnamed"), addr, size, aligned_addr, aligned_size, gettid());
        WRITE_STR_LIT(prt_buffer);
        #endif
    }

    
    // These are common for both aligned and unaligned objects
    objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].unaligned_addr = addr;
    objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].unaligned_size = size;
    objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].is_a_reference_pointer = false; // We don't know if this is a reference pointer or not, so we set it to false by default
    objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].has_been_freed = false;
    
    if (same_name && name) {
        snprintf(
            objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].name,
            MAX_OBJ_NAME_LEN-1,
            "%s_%d",
            name,
            objsnf_gvars.traced_obj_ctr + 1
        );
    } else {
        snprintf(
            objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].name,
            MAX_OBJ_NAME_LEN-1,
            "%s",
            (name ? name : "unnamed")
        );
    }

    
    snprintf(
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].type,
        MAX_TYPE_NAME_LEN-1,
        "%s",
        (type ? type : "N/A")
    );



    #if !OBJSNF_ENABLE_PKEY_BASED_LOCK
    if ( mprotect(
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].addr,
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].size,
        PROT_READ
    ) == -1) {
        printf(RED "failed\n" RESET);
        perror("mprotect@ " AT_LINE);
        return 1;
    }
    WRITE_STR_LIT(MAGENTA " mprotect success" RESET);
    #else
    // Set the pkey for the object's page to the allocated pkey
    if (pkey_mprotect(
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].addr,
        objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].size,
        PROT_READ | PROT_WRITE, // We don't wanna modify the permissions in the classic sense, just set the pkey
        objsnf_gvars.pkey
    ) == -1) {
        printf(RED "failed\n" RESET);
        perror("pkey_mprotect@ " AT_LINE);
        return 1;
    }
    #endif
    
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(GREEN " Success\n" RESET);
    #endif

    // Get the backtrace symbols for the registration call
    void * callstack[MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT];
    
    int frames = backtrace(callstack, MAX_CALL_STACK_DEPTH_FOR_SNAPSHOT);
    
    objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].call_stack = backtrace_symbols(callstack, frames);

    objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr].call_stack_size = frames;

    // Log the initial state of the object
    #if OBJSNF_ENABLE_SNAPSHOT_BATCHING // If this is enabled, then logging is done to a malloc buffer and written to disk at exit
    
    void * snapshot_buffer = wrapper_objsnf_real_malloc( size * OBJSNF_MAX_SNAPSHOTS_PER_OBJECT );


    // Add the pointer to the snapshot buffer into all the metadata array elements
    // TODO: Ideally, this buffer should be pointed to only once per object, not per snapshot
    for (int i = 0; i < OBJSNF_MAX_SNAPSHOTS_PER_OBJECT; i++) {
        objsnf_gvars.snapshot_metadata_arr[objsnf_gvars.traced_obj_ctr][i].snap_buffer = snapshot_buffer;
    }
    
    #endif

    // Call the logging function 
    if (objsnf_log_event(&objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr], false , false, NULL) != 0) {
        printf(RED "Error: " RESET "ObjSniff tracer: Failed to log initial state of object\n");
        return 1;
    }

    

    // Increment the traced object counter
    objsnf_gvars.traced_obj_ctr++;

    // Lock the pkey to prevent writing to anything
    #if OBJSNF_ENABLE_PKEY_BASED_LOCK 
    if ( pkey_set(objsnf_gvars.pkey , ICHNAEA_TRACE_READS ? PKEY_DISABLE_ACCESS : PKEY_DISABLE_WRITE)
        == -1 ) {
        perror("pkey_set@" AT_LINE);
        return 1;
    }
    #endif

    #if PRINT_STATE_INFO
    char buffer[300];
    memset(buffer, '\0', sizeof(buffer));
    snprintf(buffer, sizeof(buffer), TRACER_PRMPT GREEN "Object %s registered successfully\n" RESET, objsnf_gvars.traced_objects[objsnf_gvars.traced_obj_ctr-1].name);
    WRITE_STR_LIT(buffer);
    #endif
    
    ENABLE_SMART_ALLOC(); // Unlock the wrapped malloc

    #if PRINT_STATE_INFO
        WRITE_STR_LIT(BLUE "--------------------\n" RESET);
    #endif
    return 0;
}

int objsnf_init_tracer() {
    // hi boba

    // Return if the tracer is already initialized
    if (objsnf_gvars.tracer_initialised) return 0;

    #if PRINT_STATE_INFO
        printf(BLUE "\nObjSniff tracer version: %s Initialized" RESET "\n", __tracer__version__);
    #endif

    if ( ichnaea_state < WRAPPER_WAITING_ON_TRACER ) {
        WRITE_STR_LIT(YELLOW "Warning: " RESET "The main prgram has started before the wrapper was fully initialized, this probably will be a problem.\n");
    }
        

    #if PRINT_STATE_INFO
    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    WRITE_STR_LIT(TRACER_PRMPT "Pkey based locking is enabled\n");
    #else
    WRITE_STR_LIT(TRACER_PRMPT "Pkey based locking is disabled, using mprotect based locking\n");
    #endif
    #endif

    objsnf_gvars.tracer_initialised = 1;

    // Seed the random number generator
    srand(time(NULL));

    #if ENABLE_LOGGING
    // Create the snapshots directory if it doesn't exist, if we don't have permission to write then complain and exit
    if (mkdir("objsnf_snapshots", 0777) == -1 && errno != EEXIST) {
        perror("mkdir at " AT_LINE);
        exit(1);
    }

    

    // Chage permission of the snapshots directory to 777
    if (chmod("objsnf_snapshots", 0777) == -1) {
        perror("chmod at " AT_LINE);
        exit(1);
    }

    #endif

    // Generate a random session ID
    objsnf_gvars.session_id = time(NULL);



    
    wrapper_objsnf_dlsym_done = 1; // Set the dlsym done flag (The name of this flag is confusing, although it sets )

    // Replace the signal handler
    objsnf_replace_signal_handler();

    // Write the map of func_addr -> func_name into the snapshots directory
    objsnf_export_function_symbols_csv();

    #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    // Allocate a protection key for the tracer
    objsnf_gvars.pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
    if (objsnf_gvars.pkey == -1) {
        perror("pkey_alloc@" AT_LINE);
        exit(1);
    }
    #if PRINT_STATE_INFO
    printf(TRACER_PRMPT "Allocated pkey: %d\n", objsnf_gvars.pkey);
    #endif

    #endif

    ichnaea_state = WRAPPER_ACTIVE; // The LD preloaded library has finished initialization of the alloc wrappers (dlsyms are done)
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(TRACER_PRMPT "Tracer initialization complete\n\n");
    #endif
    return 0;
}

/*
 * Returns the index of the interrupt context with the given address
 * Returns -1 if the address is not found
*/
int objsnf_thread_has_interrupt_contexts(pid_t thread_id , interrupt_contexts_s *interrupt_ctx) {
    for (int i = 0; i < MAX_INTERRUPT_CONTEXTS; i++) {
        if ( interrupt_ctx[i].thread_id == thread_id && interrupt_ctx[i].node_state == IN_USE_NODE) {
            return i;
        }
    }
    return -1;
}

/*
 * Add interrupt context to the list of interrupt contexts
 * Returns index of added ctx on success and -1 on failure
*/
int objsnf_add_interrupt_context(pid_t thread_id, void * orig_addr,unsigned char orig_instruction,objsnf_traced_objects_s *object,interrupt_contexts_s *interrupt_ctx, bool is_obj_traced, bool is_read) {

    for (int i = 0; i < MAX_INTERRUPT_CONTEXTS; i++) {
        if (interrupt_ctx[i].node_state == END_NODE || interrupt_ctx[i].node_state == FREED_NODE) {
            interrupt_ctx[i].thread_id = thread_id;
            interrupt_ctx[i].orig_addr = orig_addr;
            interrupt_ctx[i].orig_instruction = orig_instruction;
            interrupt_ctx[i].object = object;
            interrupt_ctx[i].is_read = is_read;
            interrupt_ctx[i].node_state = IN_USE_NODE;
            interrupt_ctx[i].is_obj_traced = is_obj_traced;
            return i;
        }
    }
    return -1;
}

/*
 * Remove interrupt context from the list of interrupt contexts
 * Returns 0 on success and -1 on failure
*/
int objsnf_remove_interrupt_context(unsigned short idx, interrupt_contexts_s *interrupt_ctx) {
    if (idx >= MAX_INTERRUPT_CONTEXTS) return -1;
    if (interrupt_ctx[idx].node_state == END_NODE) interrupt_ctx[idx].node_state = END_NODE;
    else interrupt_ctx[idx].node_state = FREED_NODE;
    return 0;
}


/*
 * Check if the address is within the traced objects
 * This is a simple check that checks if the address is within the traced object's
 * address range.
 * It does not check if the address is on the same page as the traced object.
 * 
 * Returns the traced object pointer if the address is within the traced object
 * and NULL if it is not.
*/
objsnf_traced_objects_s * objsnf_address_in_traced_objects(
    void * addr_in_question,
    objsnf_traced_objects_s *traced_objects) {

    for (int i = 0; traced_objects[i].unaligned_addr != NULL ; i++) {
        // Check if the address in question is a part of the traced object
        objsnf_traced_objects_s * obj = &traced_objects[i];
        if ((uintptr_t)addr_in_question >= (uintptr_t)obj->unaligned_addr &&
            (uintptr_t)addr_in_question < (uintptr_t)obj->unaligned_addr + obj->unaligned_size) {
            return obj;
        }
    }
    return NULL;
}


/* 
 * Check if the address falls in the scope of any of the pages
 * that were locked by the traced objects. This is accidental
 * locking and cannot be avoid since mprotect is called on the whole page.
 * 
 * Returns the traced object pointer if the address is within the traced object
 * and NULL if it is not.
 *
 * TODO: Combine this in to objsnf_address_in_traced_objects
 *
*/
objsnf_traced_objects_s * objsnf_address_within_traced_objects_pg(
    void * addr_in_question,
    objsnf_traced_objects_s *traced_objects) {
    
        for (int i = 0; traced_objects[i].addr != NULL ; i++) {
            // /* Check if the address happens to be on the same first page */
            
            // Page align the address in question
            void * aligned_addr_in_question = (void *) ( (uintptr_t)addr_in_question & ~(PAGE_SIZE - 1));
    
            /* Check if the traced object occupies multiple pages and addres in question just happens to fall on that page */
            uint_fast8_t page_count = (traced_objects[i].size / PAGE_SIZE) + 1;
            for (int j = 0; j < page_count; j++) {
                // Find the next page offser starting from the traced object addr
                void * next_page_addr = (void *) ( (uintptr_t)traced_objects[i].addr + (j * PAGE_SIZE));
                // Page align the next page address
                void * aligned_next_page_addr = (void *) ( (uintptr_t)next_page_addr & ~(PAGE_SIZE - 1));
                // Check if the address in question is on the same page as the traced object
                if (aligned_addr_in_question == aligned_next_page_addr) {
                    return &traced_objects[i];
                }
            }
        }
        return NULL;
    }

// Boxed print function
// This will add a trailling newline for you
void ichnaea_boxed_print(const char *msg) {
    size_t len = strlen(msg);
    size_t box_width = len + 4; // 2 spaces on each side

    // Print top border
    printf("+");
    for (size_t i = 0; i < box_width; i++) printf("-");
    printf("+\n");

    // Print message line
    printf("|  %s  |\n", msg);

    // Print bottom border
    printf("+");
    for (size_t i = 0; i < box_width; i++) printf("-");
    printf("+\n");
}


/*
 * Helper functions to aid instruction decoding
 */
store_value_t compute_store_value(const uint8_t *ip, const void *ea, const ucontext_t *uc) {
    static __thread csh insn_emu_cap_handle = 0;
    static __thread cs_insn *insn_emu_cap_insn = NULL;

    store_value_t out = { .ok = 0, .value = 0, .width = 0 };
    
    if (insn_emu_cap_handle == 0) {

        cs_opt_mem setup;
        setup.malloc = wrapper_objsnf_zalloc_internal;
        setup.calloc = wrapper_objsnf_zalloc_calloc_internal;
        setup.realloc = wrapper_objsnf_zalloc_realloc_internal;
        setup.free = wrapper_objsnf_zalloc_free_internal;
        setup.vsnprintf = vsnprintf;

        // Finally, setup our own dynamic memory functions with cs_option().
        if (!cs_option(insn_emu_cap_handle, CS_OPT_MEM, (size_t) &setup)) { // Some how this means success 
        } else {
            // Failed to initialize our user-defined dynamic mem functions.
            // Quit is the only choice here :-(
            cs_close(&insn_emu_cap_handle);
            WRITE_STR_LIT(RED "Error: " RESET "ObjSniff tracer: Failed to set Capstone dynamic memory functions\n");
            exit(1);
        }
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &insn_emu_cap_handle) != CS_ERR_OK) return out;
        cs_option(insn_emu_cap_handle, CS_OPT_DETAIL, CS_OPT_ON);

        insn_emu_cap_insn = cs_malloc(insn_emu_cap_handle);
        if (!insn_emu_cap_insn) return out;
    }
    
    const uint8_t *code = ip;
    size_t bytes_left = 15;            // max length
    uint64_t addr = (uint64_t)(uintptr_t)ip;

    if (!cs_disasm_iter(insn_emu_cap_handle, &code, &bytes_left, &addr, insn_emu_cap_insn)) return out;

    const cs_x86 *x = &insn_emu_cap_insn->detail->x86;

    // Identify a memory destination operand (write or rmw)
    int mem_op_idx = -1;
    for (int i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_MEM && (op->access & (CS_AC_WRITE | CS_AC_READ))) {
            mem_op_idx = i;
            break;
        }
    }
    if (mem_op_idx < 0) return out;

    unsigned width = x->operands[mem_op_idx].size ? x->operands[mem_op_idx].size : 1;

    // Fast-path classes
    switch (insn_emu_cap_insn->id) {

        // ---- Plain stores: mov [mem], reg/imm ----
        case X86_INS_MOV:
        case X86_INS_MOVAPS: case X86_INS_MOVAPD:
        case X86_INS_MOVUPS: case X86_INS_MOVUPD:
        case X86_INS_MOVD:   case X86_INS_MOVQ:
        {
            // For scalar MOV, pick reg/imm source
            uint64_t src; unsigned sw;
            if (get_src_scalar(insn_emu_cap_insn, uc, &src, &sw)) {
                out.ok = 1; out.value = src; out.width = width;
                return out;
            }
            break; // SIMD paths would need XMM reads; omitted for brevity
        }

        // ---- STOS{b,w,d,q} (no REP) ----
        case X86_INS_STOSB: width = 1; goto do_stos;
        case X86_INS_STOSW: width = 2; goto do_stos;
        case X86_INS_STOSD: width = 4; goto do_stos;
        case X86_INS_STOSQ: width = 8; do_stos: {
            uint64_t rax = get_gpr64(uc, X86_REG_RAX);
            uint64_t v = narrow_to_size(rax, width, 0);
            out.ok = 1; out.value = v; out.width = width;
            return out;
        }

        // ---- Atomic/RMW arithmetic (mem is dest) ----
        case X86_INS_ADD: case X86_INS_SUB:
        case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR:
        case X86_INS_INC: case X86_INS_DEC:
        case X86_INS_NEG: case X86_INS_NOT:
        case X86_INS_XADD:
        {
            // Read old value from memory (safe: page is PROT_READ)
            uint64_t oldv = 0;
            ichnaea_memcpy(&oldv, ea, width);

            // Get source (if any)
            uint64_t src = 0; unsigned sw = width;
            get_src_scalar(insn_emu_cap_insn, uc, &src, &sw);
            uint64_t newv = apply_rmw(oldv, src, width, insn_emu_cap_insn->id);

            out.ok = 1; out.value = newv; out.width = width;
            return out;
        }

        // ---- XCHG [mem], reg ----
        case X86_INS_XCHG: {
            // mem <- reg; new mem value is reg
            uint64_t src; unsigned sw;
            if (get_src_scalar(insn_emu_cap_insn, uc, &src, &sw)) {
                out.ok = 1; out.value = narrow_to_size(src, width, 0); out.width = width;
                return out;
            }
            break;
        }

        default: break;
    }

    // Unknown/complex (REP MOVS*, CMPXCHG*, SIMD stores not handled here)
    return out;
}

/*
 * Reads GPRs from ucontext (Linux x86-64)
 */
static inline uint64_t get_gpr64(const ucontext_t *uc, unsigned cs_reg) {
    const greg_t *g = uc->uc_mcontext.gregs;
    switch (cs_reg) {
        case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX:  case X86_REG_AL: case X86_REG_AH: return g[REG_RAX];
        case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX:  case X86_REG_BL: case X86_REG_BH: return g[REG_RBX];
        case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX:  case X86_REG_CL: case X86_REG_CH: return g[REG_RCX];
        case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX:  case X86_REG_DL: case X86_REG_DH: return g[REG_RDX];
        case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI:  case X86_REG_SIL:                 return g[REG_RSI];
        case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI:  case X86_REG_DIL:                 return g[REG_RDI];
        case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP:  case X86_REG_BPL:                 return g[REG_RBP];
        case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP:  case X86_REG_SPL:                 return g[REG_RSP];
        case X86_REG_R8:  case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B:                 return g[REG_R8];
        case X86_REG_R9:  case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B:                 return g[REG_R9];
        case X86_REG_R10: case X86_REG_R10D:case X86_REG_R10W:case X86_REG_R10B:                return g[REG_R10];
        case X86_REG_R11: case X86_REG_R11D:case X86_REG_R11W:case X86_REG_R11B:                return g[REG_R11];
        case X86_REG_R12: case X86_REG_R12D:case X86_REG_R12W:case X86_REG_R12B:                return g[REG_R12];
        case X86_REG_R13: case X86_REG_R13D:case X86_REG_R13W:case X86_REG_R13B:                return g[REG_R13];
        case X86_REG_R14: case X86_REG_R14D:case X86_REG_R14W:case X86_REG_R14B:                return g[REG_R14];
        case X86_REG_R15: case X86_REG_R15D:case X86_REG_R15W:case X86_REG_R15B:                return g[REG_R15];
        case X86_REG_RIP: case X86_REG_EIP:                                                   return g[REG_RIP];
        default: return 0;
    }
}

/*
 * Narrow a value to a smaller size
 */
static inline uint64_t narrow_to_size(uint64_t v, unsigned width_bytes, unsigned high8) {
    volatile unsigned tmp = high8; // prevent compiler warnings TODO: Get rid of this
    tmp++;
    // high8==1 means AH/BH/CH/DH; caller must splice into low 16 if needed.
    switch (width_bytes) {
        case 1: return (uint8_t)v;
        case 2: return (uint16_t)v;
        case 4: return (uint32_t)v;
        default: return v;
    }
}

/*
 * Get source scalar (reg or imm) as 64-bit, plus byte width
 */
static int get_src_scalar(const cs_insn *insn, const ucontext_t *uc, uint64_t *out, unsigned *width) {
    const cs_x86 *x = &insn->detail->x86;
    // Find a non-memory write source operand (register or immediate).
    for (int i = 0; i < x->op_count; i++) {
        const cs_x86_op *op = &x->operands[i];
        if (op->type == X86_OP_REG && (op->access & CS_AC_READ)) {
            uint64_t full = get_gpr64(uc, op->reg);
            // Detect AH/BH/CH/DH: Capstone exposes them as separate regs.
            unsigned w = op->size ? op->size : 8;
            *out = narrow_to_size(full, w, 0);
            *width = w;
            return 1;
        } else if (op->type == X86_OP_IMM) {
            *out = (uint64_t)op->imm;
            *width = op->size ? op->size : 8;
            return 1;
        }
    }
    return 0;
}

/*
 * Read-modify-write compute (integer ops)
 */
static uint64_t apply_rmw(uint64_t oldv, uint64_t src, unsigned width, unsigned insn_id) {
    // mask to operand width
    uint64_t mask = (width >= 8) ? ~0ull : ((1ull << (width * 8)) - 1ull);
    oldv &= mask; src &= mask;
    switch (insn_id) {
        case X86_INS_ADD:    return (oldv + src) & mask;
        case X86_INS_SUB:    return (oldv - src) & mask;
        case X86_INS_AND:    return (oldv & src);
        case X86_INS_OR:     return (oldv | src);
        case X86_INS_XOR:    return (oldv ^ src);
        case X86_INS_INC:    return (oldv + 1) & mask;
        case X86_INS_DEC:    return (oldv - 1) & mask;
        case X86_INS_NEG:    return ((~oldv) + 1) & mask;
        case X86_INS_NOT:    return (~oldv) & mask;
        case X86_INS_XADD:   return (oldv + src) & mask; // (and src gets oldv; we only need mem)
        default:             return oldv; // fallback
    }
}