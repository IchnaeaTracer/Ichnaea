#include "wrapper.h"
/*
 * This is a wrapper for the ObjSniff tracer
 * It is used to intercept libc calls that make syscalls
 * 
 * It modifies malloc, realloc, calloc and free to always allocate 3 pages and 
 * use the first page as a guard page by offsetting the pointer by 4096 bytes
 * free is modified to free the pointer - 4096 bytes
 * 
 * TODO:
 * Allocs:-
 *  - malloc +
 *  - calloc +
 *  - realloc +
 *  - posix_memalign +
 *  - alloca + 
 *  - aligned_alloc ?
 *  - valloc ?
 *  - memalign ?
 *  - pvalloc ?
 *  - posix_fallocate ?
 *  - posix_fallocate64 ?
 *  - fallocate ?
 * 
 * 
*/

// Vars for temprorary fix for the issue where dlsym is called before the heap is initialized
#define ZALLOC_MAX 4*4096
static zalloc_obj wrapper_objsnf_zalloc_list[ZALLOC_MAX];
static size_t wrapper_objsnf_zalloc_cnt = 0;
void* wrapper_objsnf_zalloc_internal(size_t size);
int wrapper_objsnf_powerof2(unsigned long x);


/*
 * Rentrant lock to avoid recursive calls to any of the allocs 
 * this is because our allocs wrappers may use some libraries that use allocs internally
 * thus causing infinite recursion.
 * 
 * Having a lock means that if the control flow is inside
 * any of our alloc wrappers, any further calls to allocs will be directed to the real allocs.
 * 
 * This is a thread local variable to allow multiple threads to use allocs simultaneously
 * without blocking each other
 */
__thread int ichnaea_smart_alloc_lock = 0;

int fc = 0;
void free(void* ptr) {
  #if (PRINT_STATE_INFO && ALLOC_DBG)
  WRITE_STR_LIT(MAGENTA "Wrapper: " RESET "Free called\n");
  #endif


  if (!ptr) return; // Don't free NULL

  // If dlsym is not done resolving allocs, don't free memory as its probably from our temprorary zalloc
  if (ichnaea_state < WRAPPER_ALLOC_INIT_DONE) return ;

  //Catch any allocations made by zalloc and free accordingly
  for (size_t i = 0; i < wrapper_objsnf_zalloc_cnt; i++) {
    if (wrapper_objsnf_zalloc_list[i].ptr == ptr) {
      #if ALLOC_DBG
      WRITE_STR_LIT(MAGENTA "Wrapper:" RESET" Not freeing zalloced ptr\n" RESET);
      #endif
      return;
    }
  }

  // Check if it's one of the traced objects, if so, remove the pkey protection
  // IMP_TODO: It should also check if there are still other traced objects on the same page before removing the pkey protection'
  for (int i = 0; i < objsnf_gvars.traced_obj_ctr; i++) {
    if (objsnf_gvars.traced_objects[i].addr == ptr) {
      #if PRINT_STATE_INFO
      char _const_str[500] = {0};
      snprintf(_const_str, sizeof(_const_str), TRACER_PRMPT "Freeing traced object %s at %p\n" RESET, objsnf_gvars.traced_objects[i].name, ptr);
      WRITE_STR_LIT(_const_str);
      #endif

      // This is need since malloc might return this newly freed object and another handle could try to register it again
      // Which will trigger already registered problems
      objsnf_gvars.traced_objects[i].has_been_freed = true;  

      #if OBJSNF_ENABLE_PKEY_BASED_LOCK 
      // Remove the pkey protection
      if ( pkey_mprotect(ptr , objsnf_gvars.traced_objects[i].size , PROT_READ | PROT_WRITE, 0) == -1 ) {
          perror("pkey_mprotect@" AT_LINE);
          exit(1);
      }
      #else
      // Remove the mprotect protection
      if (mprotect(objsnf_gvars.traced_objects[i].addr, objsnf_gvars.traced_objects[i].size , PROT_READ | PROT_WRITE) == -1) {
          perror("mprotect@" AT_LINE );
          exit(1);
      }
      #endif

      break;
    }
  }


  #if (ALLOC_DBG)
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(_const_str), RED MAGENTA "Wrapper:" RESET" Freeing %p free count %d\n" RESET , ptr, ++fc);
  WRITE_STR_LIT(_const_str);
  #endif

  wrapper_objsnf_real_free(ptr);
}

/*
 * Wrapper for malloc
 * Any function that could potentially call malloc inside this function should be avoided (like printf)
 *  - this is to prevent infinite recursion
 * If you have no other option, use the ichnaea_smart_alloc_lock to prevent re-entrancy
 * 
 * This function allocates a fresh explicit page for every malloc call the recipient of which is a traced pointer object
 * If the user wants to trace all allocs, then this just owrks like normal malloc except for the fact that its adds every allocation to the tracing queue
 * 
*/
void *malloc(size_t size) {

  

  #if PRINT_STATE_INFO && ALLOC_DBG
    WRITE_STR_LIT( "\n" MAGENTA "Wrapper: " RESET "Malloc called and redirected to -> " );
  #endif
  // If dlsym is not done resolving allocs, use wrapper_objsnf_zalloc_internal
  if (ichnaea_state < WRAPPER_ALLOC_INIT_DONE) return wrapper_objsnf_zalloc_internal(size);

  // Since malloc can be called before the tracer is initialized by the running program,
  // we need to let other things that we don't care about use the real malloc
  // Also allow malloc to work normally when the program is exiting
  else if ( (ichnaea_state >= WRAPPER_ALLOC_INIT_DONE && ichnaea_state < WRAPPER_ACTIVE) || ichnaea_state == EXITING || ichnaea_smart_alloc_lock) {
    // A grave error has occured, we should never be here after wrapper is done wrapping the allocs
    if (!wrapper_objsnf_real_malloc) {
      WRITE_STR_LIT( RED "Error: " RESET "Something really bad just happened, the real malloc should never be NULL here at line" AT_LINE);
      exit(1);
    }

    #if PRINT_STATE_INFO && ALLOC_DBG
     WRITE_STR_LIT( "libc malloc\n" );
    #endif

    return wrapper_objsnf_real_malloc(size);
  }
  
  // This the case where the tracer is active and we need to wrap malloc to either trace all mallocs or mallos to traced objects
  else {

    #if PRINT_STATE_INFO && ALLOC_DBG
     WRITE_STR_LIT( "wrapped malloc\n" );
    #endif

    #if OBJSNF_ENABLE_SMART_ALLOCS && !OBJSNF_TRACE_ALL_ALLOCS && !ICHNAEA_ISOLATE_ALL_ALLOCS

    /* Smart malloc lock: Smart malloc needs to call malloc which causes re-entrancy issues, thus a lock. */
    if (ichnaea_smart_alloc_lock++) return wrapper_objsnf_real_malloc(size);
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(MAGENTA "Wrapper:" RESET" Smart malloc lock acquired\n" RESET);
    #endif

    
    static __thread csh handle  = 0;
    objsnf_traced_objects_s * traced_object = NULL; // Pointer to the traced object if found

    /* If there's no handle and cs_open fails, set handle to 0 and allocate a whole page for all mallocs */
    if (!handle && cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) handle = 0;
    else {
        cs_insn*            insn    = NULL;
        size_t              count   = 0;
        uint64_t            ea      = 0;

        void * rip  = __builtin_return_address(0);
        void * rbp0 = __builtin_frame_address(0);
        void * rbp1 = __builtin_frame_address(1);
        
        // Breakdown Instruction into details
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        count = cs_disasm(handle, rip, 80, 0, 6, &insn);
        uint64_t _curr_rip = (uint64_t) rip;

        if (count) {
          
            for (size_t i = 0; i < count; i++) {
                _curr_rip += insn[i].size;                  // Increment the current RIP address by the size of the instruction
                if (insn[i].id != X86_INS_MOV) continue;    // Only interested in MOV instructions
                
                #if _ENABLE_DEBUG
                printf("\n\nFound a MOV instruction at address %p " GREEN " %s %s\n" RESET, (void *)_curr_rip, insn[i].mnemonic, insn[i].op_str);
                #endif

                cs_detail *d = insn[i].detail;
                cs_x86    *x = &d->x86;

                bool has_a_register = false;
                for (size_t j = 0; j < x->op_count; ++j) { // Check if any of the operands is a register (e.g. rax, rcx, etc.)
                    cs_x86_op *op = &x->operands[j];

                    if (op->type == X86_OP_REG) {
                        switch (op->reg) {
                            case X86_REG_RAX:
                            case X86_REG_RBX:
                            case X86_REG_RCX:
                            case X86_REG_RDX:
                                has_a_register = true; // We have a register operand that is not RIP
                                break;
                            
                        }
                    }
                        
                }
                
                if (!has_a_register) continue; // If there is no register operand, then we don't care about this instruction
                
                // Loop through the operands to find a memory operand with RIP as the base register
                for (size_t operand_idx = 0; operand_idx < x->op_count; ++operand_idx) {
                    cs_x86_op *op = &x->operands[operand_idx];


                    if (op->type == X86_OP_MEM && ( op->mem.base == X86_REG_RIP || op->mem.base == X86_REG_RSP || op->mem.base == X86_REG_RBP )) { // Check if the operand is a memory operand with RIP, RSP or RBP as the base register
                        #if _ENABLE_DEBUG
                        printf("\n" MAGENTA "Found a MOV instruction with a pointer at address %p " RESET GREEN " %s %s\n" RESET, (void *)_curr_rip, insn[i].mnemonic, insn[i].op_str);
                        #endif
                        switch (op->mem.base) {
                            case X86_REG_RIP:
                                ea = _curr_rip  + op->mem.disp; // Calculate effective address using RIP
                                #if _ENABLE_DEBUG
                                printf("Effective address calculated using RIP: %p\n", (void *)ea);
                                #endif
                                break;
                            case X86_REG_RSP:
                                ea = (uint64_t)(rbp0 + sizeof(void *) + op->mem.disp + 8); // Calculate effective address using RSP
                                #if _ENABLE_DEBUG
                                printf("Effective address calculated using RSP: %p\n", (void *)ea);
                                #endif
                                break;
                            case X86_REG_RBP:                                                               // 808 , 88 = 24 = 24
                                // ea = (uint64_t)(rbp0 + 24);//op->mem.disp ); // Calculate effective address using RBP 832 , 112
                                ea = (uint64_t)(rbp1 + op->mem.disp ); // Calculate effective address using RBP 832 , 112

                                #if _ENABLE_DEBUG
                                printf("Effective address calculated using RBP: %p\n", (void *)ea);
                                #endif
                                break;
                            default:
                                printf(RED "Error: " RESET "Unknown base register in MOV instruction\n");
                        }
                        break;
                    }
                }

                if (ea != 0) break; // If we found a MOV instruction with a pointer, break the loop
            }
        }
        cs_close(&handle); // TODO: Test if a capstone handle can be resused or not???
        cs_free(insn, count);

        // If we can't compute the effective address, just return the real malloc
        if (!ea) {
          ichnaea_smart_alloc_lock = 0; // Unlock malloc
          return wrapper_objsnf_real_malloc(size);
        }
        
        
        
        // Go through all traced objects and check if the pointer is in the list
        int  obj_idx = 0;
        
        bool found = false;
        for (; obj_idx < objsnf_gvars.traced_obj_ctr; obj_idx++) {
          if (objsnf_gvars.traced_objects[obj_idx].unaligned_addr == (void *)ea) {
            found = true; // Found the object
            break; // Found the object
          }
        }

        // If the pointer is not in the traced objects, just call the real malloc
        if (!found) {
          ichnaea_smart_alloc_lock = 0; // Unlock malloc
          return wrapper_objsnf_real_malloc(size);
        }

        traced_object = &objsnf_gvars.traced_objects[obj_idx];

        #if PRINT_STATE_INFO
        char _const_str[500] = {0};
        snprintf(_const_str, sizeof(_const_str), TRACER_PRMPT CYAN "Found a traced object at %p with name '%s' being malloced\n" RESET, traced_object->unaligned_addr, traced_object->name);
        WRITE_STR_LIT(_const_str);
        #endif
      }


    #elif OBJSNF_TRACE_ALL_ALLOCS
    
    /* Smart malloc lock: Smart malloc needs to call malloc which causes re-entrancy issues, thus a lock. */
    if (ichnaea_smart_alloc_lock++) return wrapper_objsnf_real_malloc(size);
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(MAGENTA "Wrapper:" RESET" Smart malloc lock acquired\n" RESET);
    #endif
    
    #endif
    

    size_t final_sz = ( (size + PAGE_SIZE - 1)  / PAGE_SIZE) * PAGE_SIZE;
    void * ptr = wrapper_objsnf_real_memalign(PAGE_SIZE, final_sz); // Use memalign to get page aligned memory
    

    #if OBJSNF_TRACE_ALL_ALLOCS
      char name[25] = "malloced-obj-";
      // Add the object counter to the name
      snprintf(name + strlen(name), 25 - strlen(name), "%d", objsnf_gvars.traced_obj_ctr + 1);
      if (size > 0) {
        objsnf_register_object(
          ptr, 
          size, // We use the last page as a guard page
          name, 
          "malloced-all"
        );
      }
      ichnaea_smart_alloc_lock = 0; // Unlock malloc
      #if PRINT_STATE_INFO
      WRITE_STR_LIT(MAGENTA "Wrapper:" RESET" Smart malloc lock released\n" RESET); 
      #endif
    #endif
    

    #if ALLOC_DBG
    char const_str[500] = {0};
    snprintf(const_str, sizeof(const_str), GREEN MAGENTA "Wrapper:" RESET" malloc(%ld) = %p\n" RESET, size, ptr);
    WRITE_STR_LIT(const_str);
    #endif
    
    #if OBJSNF_ENABLE_SMART_ALLOCS && !OBJSNF_TRACE_ALL_ALLOCS && !ICHNAEA_ISOLATE_ALL_ALLOCS
    // Register the new object in the traced objects
    if (ptr != NULL) {
      char obj_name[100] = {0};
      snprintf(obj_name, sizeof(obj_name), "malloced-%s", traced_object->name);
      objsnf_register_object(
        ptr, 
        size, // We use the last page as a guard page
        obj_name, 
        traced_object->type
      );
    }
    ichnaea_smart_alloc_lock = 0; // Unlock malloc
    #endif
    
    return ptr;
  }
}


void *calloc(size_t nmemb, size_t size) {
  #if PRINT_STATE_INFO && ALLOC_DBG
    WRITE_STR_LIT( "\n" MAGENTA "Wrapper: " RESET "Calloc called and redirected to -> " );
  #endif

  // If dlsym is not done resolving allocs, use wrapper_objsnf_zalloc_internal
  if (ichnaea_state < WRAPPER_ALLOC_INIT_DONE) {
    void * _ptr = wrapper_objsnf_zalloc_internal(size);
    if (_ptr != NULL) memset(_ptr, 0, size);
    else {
       WRITE_STR_LIT( RED MAGENTA " zalloc\n" );
       exit(1);
    }
    return _ptr;
  }

  // Since malloc can be called before the tracer is initialized by the running program,
  // we need to let other things that we don't care about use malloc normally
  // Also allow malloc to work normally when the tool is exiting
  else if ( (ichnaea_state >= WRAPPER_ALLOC_INIT_DONE && ichnaea_state < WRAPPER_ACTIVE) || ichnaea_state == EXITING || ichnaea_smart_alloc_lock) {
    // A grave error has occured, we should never be here after wrapper is done wrapping the allocs
    if (!wrapper_objsnf_real_calloc) {
      WRITE_STR_LIT( RED "Error: " RESET "Something really bad just happened, the real calloc should never be NULL here at line" AT_LINE);
      exit(1);
    }

    #if PRINT_STATE_INFO && ALLOC_DBG
      if (ichnaea_state == EXITING) {
        WRITE_STR_LIT( "libc calloc during EXITING\n" );
      } else if (ichnaea_smart_alloc_lock) {
        WRITE_STR_LIT( "libc calloc due to smart alloc lock\n" );
      } else if (ichnaea_state < WRAPPER_ALLOC_INIT_DONE) {
        WRITE_STR_LIT( "libc calloc during ALLOC INIT NOT DONE\n" );
      } else {
        WRITE_STR_LIT( "libc calloc during WRAPPER INIT DONE but not ACTIVE\n" );
      }
    #endif

    return wrapper_objsnf_real_calloc(nmemb, size);
  }

  // This the case where the tracer is active and we need to wrap calloc to either traced all callocs or callos to traced objects
  else {
    #if PRINT_STATE_INFO && ALLOC_DBG
     WRITE_STR_LIT( "wrapped calloc\n" );
    #endif

    if (nmemb == 0 || size == 0) return NULL; // Avoid overflow

    #if (OBJSNF_ENABLE_SMART_ALLOCS && !OBJSNF_TRACE_ALL_ALLOCS && !ICHNAEA_ISOLATE_ALL_ALLOCS)

    /* Smart malloc lock: Smart malloc needs to call malloc which causes re-entrancy issues, thus a lock. */
    if (ichnaea_smart_alloc_lock++) return wrapper_objsnf_real_calloc(nmemb, size);

    
    static __thread csh handle  = 0;
    objsnf_traced_objects_s * traced_object = NULL; // Pointer to the traced object if found

    /* If there's no handle and cs_open fails, set handle to 0 and allocate a whole page for all mallocs */
    if (!handle && cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) handle = 0;
    else {
        cs_insn*            insn    = NULL;
        size_t              count   = 0;
        uint64_t            ea      = 0;

        void * rip  = __builtin_return_address(0);
        void * rbp0 = __builtin_frame_address(0);
        void * rbp1 = __builtin_frame_address(1);
        
        // Breakdown Instruction into details
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        count = cs_disasm(handle, rip, 80, 0, 6, &insn);
        uint64_t _curr_rip = (uint64_t) rip;

        if (count) {
          
            for (size_t i = 0; i < count; i++) {
                _curr_rip += insn[i].size;                  // Increment the current RIP address by the size of the instruction
                if (insn[i].id != X86_INS_MOV) continue;    // Only interested in MOV instructions
                
                #if _ENABLE_DEBUG
                printf("\n\nFound a MOV instruction at address %p " GREEN " %s %s\n" RESET, (void *)_curr_rip, insn[i].mnemonic, insn[i].op_str);
                #endif

                cs_detail *d = insn[i].detail;
                cs_x86    *x = &d->x86;

                bool has_a_register = false;
                for (size_t j = 0; j < x->op_count; ++j) { // Check if any of the operands is a register (e.g. rax, rcx, etc.)
                    cs_x86_op *op = &x->operands[j];

                    if (op->type == X86_OP_REG) {
                        switch (op->reg) {
                            case X86_REG_RAX:
                            case X86_REG_RBX:
                            case X86_REG_RCX:
                            case X86_REG_RDX:
                                has_a_register = true; // We have a register operand that is not RIP
                                break;
                            
                        }
                    }
                        
                }
                
                if (!has_a_register) continue; // If there is no register operand, then we don't care about this instruction
                
                // Loop through the operands to find a memory operand with RIP as the base register
                for (size_t operand_idx = 0; operand_idx < x->op_count; ++operand_idx) {
                    cs_x86_op *op = &x->operands[operand_idx];


                    if (op->type == X86_OP_MEM && ( op->mem.base == X86_REG_RIP || op->mem.base == X86_REG_RSP || op->mem.base == X86_REG_RBP )) { // Check if the operand is a memory operand with RIP, RSP or RBP as the base register
                        #if _ENABLE_DEBUG
                        printf("\n" MAGENTA "Found a MOV instruction with a pointer at address %p " RESET GREEN " %s %s\n" RESET, (void *)_curr_rip, insn[i].mnemonic, insn[i].op_str);
                        #endif
                        switch (op->mem.base) {
                            case X86_REG_RIP:
                                ea = _curr_rip  + op->mem.disp; // Calculate effective address using RIP
                                #if _ENABLE_DEBUG
                                printf("Effective address calculated using RIP: %p\n", (void *)ea);
                                #endif
                                break;
                            case X86_REG_RSP:
                                ea = (uint64_t)(rbp0 + sizeof(void *) + op->mem.disp + 8); // Calculate effective address using RSP
                                #if _ENABLE_DEBUG
                                printf("Effective address calculated using RSP: %p\n", (void *)ea);
                                #endif
                                break;
                            case X86_REG_RBP:                                                               // 808 , 88 = 24 = 24
                                // ea = (uint64_t)(rbp0 + 24);//op->mem.disp ); // Calculate effective address using RBP 832 , 112
                                ea = (uint64_t)(rbp1 + op->mem.disp ); // Calculate effective address using RBP 832 , 112

                                #if _ENABLE_DEBUG
                                printf("Effective address calculated using RBP: %p\n", (void *)ea);
                                #endif
                                break;
                            default:
                                printf(RED "Error: " RESET "Unknown base register in MOV instruction\n");
                        }
                        break;
                    }
                }

                if (ea != 0) break; // If we found a MOV instruction with a pointer, break the loop
            }
        }
        cs_close(&handle); // TODO: Test if a capstone handle can be resused or not???
        cs_free(insn, count);

        // If we can't compute the effective address, just return the real malloc
        if (!ea) {
          ichnaea_smart_alloc_lock = 0; // Unlock malloc
          return wrapper_objsnf_real_calloc(nmemb, size);
        }
        
        
        
        // Go through all traced objects and check if the pointer is in the list
        int  obj_idx = 0;
        
        bool found = false;
        for (; obj_idx < objsnf_gvars.traced_obj_ctr; obj_idx++) {
          if (objsnf_gvars.traced_objects[obj_idx].unaligned_addr == (void *)ea) {
            found = true; // Found the object
            break; // Found the object
          }
        }

        // If the pointer is not in the traced objects, just call the real malloc
        if (!found) {
          ichnaea_smart_alloc_lock = 0; // Unlock malloc
          return wrapper_objsnf_real_calloc(nmemb, size);
        }
        // WRITE_STR_LIT( BLUE "FLAG!!\n" RESET);
        traced_object = &objsnf_gvars.traced_objects[obj_idx];

        #if PRINT_STATE_INFO
        char _const_str[500] = {0};
        snprintf(_const_str, sizeof(_const_str), TRACER_PRMPT CYAN "Found a traced object at %p with name '%s' being calloced\n" RESET, traced_object->unaligned_addr, traced_object->name);
        WRITE_STR_LIT(_const_str);
        #endif
      }


    #elif OBJSNF_TRACE_ALL_ALLOCS
    
    /* Smart malloc lock: Smart malloc needs to call malloc which causes re-entrancy issues, thus a lock. */
    if (ichnaea_smart_alloc_lock++) return wrapper_objsnf_real_calloc(nmemb, size);
    
    #endif

    size_t final_sz = ( (nmemb * size + PAGE_SIZE - 1)  / PAGE_SIZE) * PAGE_SIZE;
    void * ptr = wrapper_objsnf_real_memalign(PAGE_SIZE, final_sz); // Use memalign to get page aligned memory
    

    #if OBJSNF_TRACE_ALL_ALLOCS
      char name[25] = "calloced-obj-";
      // Add the object counter to the name
      snprintf(name + strlen(name), 25 - strlen(name), "%d", objsnf_gvars.traced_obj_ctr + 1);
      if (size > 0) {
        objsnf_register_object(
          ptr, 
          nmemb * size, // We use the last page as a guard page
          name, 
          "calloced-all"
        );
      }
      ichnaea_smart_alloc_lock = 0; // Unlock malloc
    #endif


    #if ALLOC_DBG
    char const_str[500] = {0};
    snprintf(const_str, sizeof(const_str), GREEN MAGENTA "Wrapper:" RESET" malloc(%ld) = %p\n" RESET, size, ptr);
    WRITE_STR_LIT(const_str);
    #endif
    
    #if OBJSNF_ENABLE_SMART_ALLOCS && !OBJSNF_TRACE_ALL_ALLOCS && !ICHNAEA_ISOLATE_ALL_ALLOCS
    // Register the new object in the traced objects
    if (ptr != NULL) {
      char obj_name[100] = {0};
      snprintf(obj_name, sizeof(obj_name), "calloced-%s", traced_object->name);
      objsnf_register_object(
        ptr, 
        nmemb * size, // We use the last page as a guard page
        obj_name, 
        traced_object->type
      );
    }
    ichnaea_smart_alloc_lock = 0; // Unlock malloc
    #endif

    memset(ptr, 0, nmemb * size); // Zero out the memory uptil nmemb * size (leave the rest of the page uninitialized)

    #if ALLOC_DBG
    // char const_str[500] = {0};
    snprintf(const_str, sizeof(const_str), GREEN MAGENTA "Wrapper:" RESET" calloc(%ld, %ld) = %p\n" RESET, nmemb, size, ptr);
    WRITE_STR_LIT(const_str);
    #endif
    return ptr;
  }
}


void *realloc(void* ptr, size_t size) {
  // TODO:
  // Check this implimentation throughly
  // A lot of things are wrong with this implimentation
  // If dlsym is not done resolving allocs, use wrapper_objsnf_zalloc_internal
  if (ichnaea_state < WRAPPER_ALLOC_INIT_DONE) {
    void * new_pointer =  wrapper_objsnf_zalloc_internal(size);

    if (new_pointer == NULL) {
      #if PRINT_STATE_INFO && ALLOC_DBG
       WRITE_STR_LIT( RED MAGENTA "Wrapper: " RESET "realloc returning NULL from zalloc\n" );
      #endif
       exit(1);
    }

    // Copy the old data if ptr is not NULL
    if (ptr) {
      ichnaea_memcpy(new_pointer, ptr, size); // Copy the old data to the new location
      return new_pointer;
    }
    return new_pointer;
  }

  // Since malloc can be called before the tracer is initialized by the running program,
  // we need to let other things that we don't care about use malloc normally
  else if (ichnaea_state >= WRAPPER_ALLOC_INIT_DONE && ichnaea_state < WRAPPER_ACTIVE ) {
    // A grave error has occured, we should never be here after wrapper is done wrapping the allocs
    if (!wrapper_objsnf_real_realloc) {
      WRITE_STR_LIT( RED "Error: " RESET "Something really bad just happened, the real realloc should never be NULL here at line" AT_LINE);
      exit(1);
    }

    #if PRINT_STATE_INFO && ALLOC_DBG
     WRITE_STR_LIT( MAGENTA "Wrapper:" RESET" realloc called before tracer init, returning normal realloc\n" );
    #endif

    return wrapper_objsnf_real_realloc(ptr, size);
  }

  // Chk if the address is from wrapper_objsnf_zalloc_internal
  for (size_t i = 0; i < wrapper_objsnf_zalloc_cnt; i++) {
    if (wrapper_objsnf_zalloc_list[i].ptr == ptr) {
      /* If dlsym cleans up its dynamic memory allocated with wrapper_objsnf_zalloc_internal,
       * we intercept and ignore it, as well as the resulting mem leaks.
       * On the tested system, this did not happen
       * NOTE: This will lead to a memory leak!
       */
      void * __addr =  wrapper_objsnf_real_malloc(size);
      if (ptr && __addr) {
        ichnaea_memcpy(__addr, ptr, wrapper_objsnf_zalloc_list[i].size < size ? wrapper_objsnf_zalloc_list[i].size : size); // Copy the old data to the new
      }
      #if ALLOC_DBG
      char const_str[500] = {0};
      snprintf(const_str, sizeof(const_str), GREEN MAGENTA "Wrapper:" RESET" zalloc-realloc(%p, %ld) = %p\n" RESET, ptr, size, __addr);
      WRITE_STR_LIT(const_str);
      #endif
      return __addr;
    }
  }

  // Using malloc
  if (!ptr) return wrapper_objsnf_real_malloc(size); // If ptr is NULL, use malloc

  // We don't cover realloc
  void * rtn_ptr = wrapper_objsnf_real_realloc(ptr, size);

  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), GREEN MAGENTA "Wrapper:" RESET" realloc(%p, %ld) = %p\n" RESET, ptr, size, rtn_ptr);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn_ptr;
}

/*
 * Since posix memalign is called when explicit alignment is needed, we just call the real posix_memalign
 * TODO: Ideally, we should
 * -- allocate a whole page and return an address inside that page that is aligned to the requested alignment
 * -- also, we should trace the objects allocated by this tool if all allocs are being traced
 * For now, we just call the real posix_memalign
 */
// int posix_memalign(void **memptr, size_t alignment, size_t size) {
//   // We dont support wrapping posix_memalign
// }

/*
 * This should do the same as posix_memalign but return the pointer directly instead of using a double pointer (e.g. void **memptr)
*/
// void *aligned_alloc(size_t alignment, size_t size) {
//   // Not supported yet
// }

// Dlsym needs heap but we can't use actual heap while dlsym is being called to find actual heap
// Catch 22 situation here so we use mmap to allocate memory
void* wrapper_objsnf_zalloc_internal(size_t size) {
  #if PRINT_STATE_INFO && ALLOC_DBG
  WRITE_STR_LIT( " Internal zalloc\n" );
  #endif

  if (wrapper_objsnf_zalloc_cnt >= ZALLOC_MAX-1) return NULL;

  /* Anonymous mapping ensures that pages are zero'd */
  void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  
  if (MAP_FAILED == ptr) {
    WRITE_STR_LIT(RED "error: " RESET MAGENTA "Wrapper:" RESET" wrapper_objsnf_zalloc_internal mmap failed\n");
    return NULL;
  }

  /* keep track for later calls to free */
  wrapper_objsnf_zalloc_cnt++;
  wrapper_objsnf_zalloc_list[wrapper_objsnf_zalloc_cnt].size = size;
  wrapper_objsnf_zalloc_list[wrapper_objsnf_zalloc_cnt].ptr = ptr;


  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), MAGENTA MAGENTA "Wrapper:" RESET" Allocated via wrapper_objsnf_zalloc_internal: %p\n" RESET, ptr);
  WRITE_STR_LIT( const_str );
  #endif

  return ptr;
}

//A zalloc based calloc version
void* wrapper_objsnf_zalloc_calloc_internal(size_t nmemb, size_t size) {
  #if PRINT_STATE_INFO && ALLOC_DBG
  WRITE_STR_LIT( " Internal zalloc-calloc\n" );
  #endif
  size_t total_size = nmemb * size;
  return wrapper_objsnf_zalloc_internal(total_size);
}

// A zalloc based realloc version
void* wrapper_objsnf_zalloc_realloc_internal(void* old_ptr, size_t size) {
  #if PRINT_STATE_INFO && ALLOC_DBG
  WRITE_STR_LIT( " Internal zalloc-realloc\n" );
  #endif
  void * new_pointer =  wrapper_objsnf_zalloc_internal(size);
  if (new_pointer == NULL) {
    #if PRINT_STATE_INFO && ALLOC_DBG
     WRITE_STR_LIT( RED MAGENTA "Wrapper: " RESET "realloc returning NULL from zalloc\n" );
    #endif
     exit(1);
  }
  // Copy the old data if old_ptr is not NULL
  if (old_ptr) {
    ichnaea_memcpy(new_pointer, old_ptr, size); // Copy the old data to the new location
    return new_pointer;
  }
  return new_pointer;
}

// Fake free for zalloced memory (We be lekin memory here since I have no help)
void wrapper_objsnf_zalloc_free_internal(void* ptr) {
  (void)ptr; // Unused parameter
  #if PRINT_STATE_INFO && ALLOC_DBG
  WRITE_STR_LIT( MAGENTA "Wrapper:" RESET" Internal zalloc free called\n" );
  #endif
  // We do nothing here to avoid freeing memory allocated by zalloc
  return;
}

// Function to check if a number is a power of 2
int wrapper_objsnf_powerof2(unsigned long x) {
    return (x != 0) && ((x & (x - 1)) == 0);
}
