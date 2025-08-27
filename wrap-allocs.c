#include "wrapper.h"

// Vars for temprorary fix for the issue where dlsym is called before the heap is initialized
#define ZALLOC_MAX 4*4096
static zalloc_obj wrapper_objsnf_zalloc_list[ZALLOC_MAX];
static size_t wrapper_objsnf_zalloc_cnt = 0;
void* wrapper_objsnf_zalloc_internal(size_t size);
int wrapper_objsnf_powerof2(unsigned long x);

// Alloc wrapper flags
__thread int objsnf_smart_malloc_lock = 0; // Rentrant lock to avoid recursive calls to malloc
__thread int objsnf_custom_alloc_lock = 0; // Rentrant lock to avoid recursive calls to custom allocators (not sure if this is required but good to have)


void * allocate_isloated_if_traced(size_t size) {

  if (objsnf_custom_alloc_lock++) return wrapper_objsnf_real_malloc(size);

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
      
      // Breakdown 6 Instructions after the instruction at the return address into details
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
        objsnf_smart_malloc_lock = 0; // Unlock malloc
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
        objsnf_smart_malloc_lock = 0; // Unlock malloc
        return wrapper_objsnf_real_malloc(size);
      }
      // WRITE_STR_LIT( BLUE "FLAG!!\n" RESET);
      traced_object = &objsnf_gvars.traced_objects[obj_idx];

      #if PRINT_STATE_INFO
      char _const_str[500] = {0};
      snprintf(_const_str, sizeof(_const_str), TRACER_PRMPT CYAN "Found a traced object at %p with name '%s' being malloced\n" RESET, traced_object->unaligned_addr, traced_object->name);
      WRITE_STR_LIT(_const_str);
      #endif

      // Now since we know it's a address of a pointer to a traced object, we can unlock the object
      if (!traced_object->is_a_reference_pointer) {
        traced_object->is_a_reference_pointer = true; // Set the flag to true
        if ( mprotect(traced_object->addr, traced_object->unaligned_size, PROT_READ | PROT_WRITE) != 0) {
          WRITE_STR_LIT(RED "Error: " RESET "wrap-allocs.c: mprotect failed at " AT_LINE " \n" );
        }
      }
    }
}


void free(void* ptr) {

  char _const_str[500] = {0};

  if (!ptr) return; // Don't free NULL, TODO: See why this is happening

  if (wrapper_objsnf_alloc_init_pending) return;
  if(!wrapper_objsnf_real_malloc) alloc_init();

  //Catch any allocations made by zalloc and free accordingly
  for (size_t i = 0; i < wrapper_objsnf_zalloc_cnt; i++) {
    snprintf(_const_str, sizeof(_const_str), RED "CHECKING ZALLOC\n" RESET);
    WRITE_STR_LIT(_const_str);
    if (wrapper_objsnf_zalloc_list[i].ptr == ptr) {
      zalloc_obj obj = wrapper_objsnf_zalloc_list[i];

      /*void function and no error return so nothing 
      is really done about failed munmap - return regardless*/
      int ret = munmap(obj.ptr, obj.size); /*returns -1 on faliure and 0 on success */

      if(ret < 0){

        #if ENABLE_WARNINGS
        WRITE_STR_LIT( YELLOW "wrap-free: " RESET "Warning: munmap failure\n");
        #endif

      }else{
        continue;
      }

      return;
    }
  }


  #if ALLOC_DBG
  snprintf(_const_str, sizeof(_const_str), RED MAGENTA "wrap-preload:" RESET" Freeing %p #%ld\n" RESET , ptr , wrapper_objsnf_free_count);
  WRITE_STR_LIT(_const_str);
  #endif

  wrapper_objsnf_real_free(ptr);
}

void *malloc(size_t size) {
  
  if ( wrapper_objsnf_alloc_init_pending) return wrapper_objsnf_zalloc_internal(size); // If dlsym is not done, use wrapper_objsnf_zalloc_internal
  if ( !wrapper_objsnf_real_malloc) alloc_init();
  if ( objsnf_gvars.tracer_cleanup_done) return wrapper_objsnf_real_malloc(size);
  

  
  #if OBJSNF_ENABLE_SMART_ALLOCS

  /* Smart malloc lock: Smart malloc needs to call malloc which causes re-entrancy issues, thus a lock. */
  if (objsnf_smart_malloc_lock++) return wrapper_objsnf_real_malloc(size);

  
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
        objsnf_smart_malloc_lock = 0; // Unlock malloc
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
        objsnf_smart_malloc_lock = 0; // Unlock malloc
        return wrapper_objsnf_real_malloc(size);
      }
      // WRITE_STR_LIT( BLUE "FLAG!!\n" RESET);
      traced_object = &objsnf_gvars.traced_objects[obj_idx];

      #if PRINT_STATE_INFO
      char _const_str[500] = {0};
      snprintf(_const_str, sizeof(_const_str), TRACER_PRMPT CYAN "Found a traced object at %p with name '%s' being malloced\n" RESET, traced_object->unaligned_addr, traced_object->name);
      WRITE_STR_LIT(_const_str);
      #endif

      // Now since we know it's a address of a pointer to a traced object, we can unlock the object
      if (!traced_object->is_a_reference_pointer) {
        traced_object->is_a_reference_pointer = true; // Set the flag to true
        if ( mprotect(traced_object->addr, traced_object->unaligned_size, PROT_READ | PROT_WRITE) != 0) {
          WRITE_STR_LIT(RED "Error: " RESET "wrap-allocs.c: mprotect failed at " AT_LINE " \n" );
        }
      }
    }


  #endif


    
  size_t final_sz = ( (size + PAGE_SIZE - 1)  / PAGE_SIZE) * PAGE_SIZE;

  void * ptr = wrapper_objsnf_real_memalign(PAGE_SIZE, final_sz); // Use memalign to get page aligned memory

  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), GREEN MAGENTA "wrap-preload:" RESET" malloc(%ld) = %p #%ld\n" RESET, size, ptr , wrapper_objsnf_alloc_count);
  WRITE_STR_LIT(const_str);
  #endif
  
  #if OBJSNF_ENABLE_SMART_ALLOCS
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
  objsnf_smart_malloc_lock = 0; // Unlock malloc
  #endif
  
  return ptr;
}

void *realloc(void* ptr, size_t size) {
  if (wrapper_objsnf_alloc_init_pending) {
    if (ptr) {
      WRITE_STR_LIT(RED MAGENTA "wrap-preload:" RESET" realloc-ing not supported this soon, exiting\n" RESET);
      exit(1);
    }
    return wrapper_objsnf_zalloc_internal(size);
  }

  if(!wrapper_objsnf_real_malloc) alloc_init();
  if (objsnf_gvars.tracer_cleanup_done) return wrapper_objsnf_real_realloc(ptr, size);


  // Chk if the address is from wrapper_objsnf_zalloc_internal
  for (size_t i = 0; i < wrapper_objsnf_zalloc_cnt; i++) {
    if (wrapper_objsnf_zalloc_list[i].ptr == ptr) {
      /* If dlsym cleans up its dynamic memory allocated with wrapper_objsnf_zalloc_internal,
       * we intercept and ignore it, as well as the resulting mem leaks.
       * On the tested system, this did not happen
       * NOTE: This will lead to a memory leak!
       */
      void * __addr =  wrapper_objsnf_real_realloc(ptr, size);
      #if ALLOC_DBG
      char const_str[500] = {0};
      snprintf(const_str, sizeof(const_str), GREEN MAGENTA "wrap-preload:" RESET" zalloc-realloc(%p, %ld) = %p #%ld\n" RESET, ptr, size, __addr , wrapper_objsnf_alloc_count);
      WRITE_STR_LIT(const_str);
      #endif
      return __addr;
    }
  }

  // Using realloc to allocate memory which is dumb
  if (!ptr) return malloc(size); // If ptr is NULL, use malloc

  // We don't cover realloc
  void * rtn_ptr = wrapper_objsnf_real_realloc(ptr, size);
 
  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), GREEN MAGENTA "wrap-preload:" RESET" realloc(%p, %ld) = %p #%ld\n" RESET, ptr, size, rtn_ptr , wrapper_objsnf_alloc_count);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn_ptr;
}

void *calloc(size_t nmemb, size_t size) {
  /* Be aware of integer overflow in nmemb*size.
   * Can only be triggered by dlsym */
  
  if (wrapper_objsnf_alloc_init_pending) return wrapper_objsnf_zalloc_internal(nmemb * size); // If dlsym is not done, use wrapper_objsnf_zalloc_internal
  if(!wrapper_objsnf_real_malloc) alloc_init();
  if (objsnf_gvars.tracer_cleanup_done) return wrapper_objsnf_real_calloc(nmemb, size);
  if (nmemb == 0 || size == 0) return NULL; // Avoid overflow

  size_t final_sz = ( ( (nmemb * size) + PAGE_SIZE - 1)  / PAGE_SIZE) * PAGE_SIZE; // Align to page size

  void * __addr = wrapper_objsnf_real_memalign(PAGE_SIZE, final_sz); // Use memalign to get page aligned memory

  memset(__addr, 0, final_sz); // Zero out the memory

  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), GREEN MAGENTA "wrap-preload:" RESET" calloc(%ld, %ld) = %p #%ld\n" RESET, nmemb, size, __addr , wrapper_objsnf_alloc_count);
  WRITE_STR_LIT(const_str);
  #endif
  return __addr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
  // TODO: What if a traced object is allocated with posix memalign?? Ignore the variable?
  #if ALLOC_DBG
  WRITE_STR_LIT(BLUE MAGENTA "wrap-preload:" RESET" POSIX_memalign caught\n" RESET);
  #endif
  if (wrapper_objsnf_alloc_init_pending) {
    // return wrapper_objsnf_zalloc_internal(size);
    // TODO: Add support for it later
    WRITE_STR_LIT(RED MAGENTA "wrap-preload:" RESET" posix_memalign not supported this soon, exiting\n" RESET);
    exit(1);
  }
  if(!wrapper_objsnf_real_malloc) alloc_init();
  if (objsnf_gvars.tracer_cleanup_done) return wrapper_objsnf_posix_memalign(memptr, alignment, size);

  /* Test whether the SIZE argument is valid.  It must be a power of
    two multiple of sizeof (void *).  */
  if (alignment % sizeof (void *) != 0 || !wrapper_objsnf_powerof2 (alignment / sizeof (void *)) || alignment == 0) return EINVAL;

  // Call the original posix_memalign
  int code = wrapper_objsnf_posix_memalign( memptr , alignment > PAGE_SIZE ?  alignment : PAGE_SIZE , size);

  if (code != 0) return code;

  #if ALLOC_DBG
  char const_str[500];
  snprintf(const_str, sizeof(const_str), MAGENTA MAGENTA "wrap-preload:" RESET" posix_memalign( %p, %ld, %ld) = %d" , *memptr, alignment, size, code);
  WRITE_STR_LIT(const_str);
  #endif

  return 0;
}

void *aligned_alloc(size_t alignment, size_t size) {
  #if ALLOC_DBG
  WRITE_STR_LIT(BLUE MAGENTA "wrap-preload:" RESET" aligned_alloc caught\n" RESET);
  #endif
  if (wrapper_objsnf_alloc_init_pending) return wrapper_objsnf_zalloc_internal(size); // If dlsym is not done, use wrapper_objsnf_zalloc_internal
  if(!wrapper_objsnf_real_malloc) alloc_init();
  if (objsnf_gvars.tracer_cleanup_done) return wrapper_objsnf_real_aligned_alloc(alignment, size);

  /* Test whether the SIZE argument is valid.  It must be a power of
    two multiple of sizeof (void *).  */
  if (alignment % sizeof (void *) != 0 || !wrapper_objsnf_powerof2 (alignment / sizeof (void *)) || alignment == 0) return NULL;

  void * __tmp_ptr = wrapper_objsnf_real_memalign( alignment > PAGE_SIZE ? alignment : PAGE_SIZE , size);

  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), MAGENTA MAGENTA "wrap-preload:" RESET" aligned_alloc(%ld, %ld) = %p #%ld\n" RESET, alignment, size, __tmp_ptr , wrapper_objsnf_alloc_count);
  WRITE_STR_LIT(const_str);
  #endif

  return __tmp_ptr;
}

// Dlsym needs heap but we can't use actual heap while dlsym is being called to find actual heap
// Catch 22 situation here so we use mmap to allocate memory
void* wrapper_objsnf_zalloc_internal(size_t size) {
  #if PRINT_STATE_INFO
  WRITE_STR_LIT( MAGENTA "wrap-preload:" RESET" Internal zalloc called\n" );
  #endif

  if (wrapper_objsnf_zalloc_cnt >= ZALLOC_MAX-1) return NULL;

  /* Anonymous mapping ensures that pages are zero'd */
  void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  
  if (MAP_FAILED == ptr) {
    WRITE_STR_LIT(RED "error: " RESET MAGENTA "wrap-preload:" RESET" wrapper_objsnf_zalloc_internal mmap failed\n");
    return NULL;
  }

 
  // #if ALLOC_DBG
  // char const_str[500] = {0};
  // snprintf(const_str, sizeof(const_str), GREEN "Updating entry #%d with ptr:%p and size: %zu\n" RESET, wrapper_objsnf_alloc_count, ptr , size);
  // WRITE_STR_LIT(const_str);
  // #endif

  /* keep track for later calls to free */
  wrapper_objsnf_zalloc_cnt++;
  wrapper_objsnf_zalloc_list[wrapper_objsnf_zalloc_cnt].size = size;
  wrapper_objsnf_zalloc_list[wrapper_objsnf_zalloc_cnt].ptr = ptr;


  #if ALLOC_DBG
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str), MAGENTA MAGENTA "wrap-preload:" RESET" Allocated via wrapper_objsnf_zalloc_internal: %p\n" RESET, ptr);
  WRITE_STR_LIT( const_str );
  #endif

  return ptr;
}

// Function to check if a number is a power of 2
int wrapper_objsnf_powerof2(unsigned long x) {
    return (x != 0) && ((x & (x - 1)) == 0);
}
