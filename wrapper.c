#include "wrapper.h"

// Dlsym stat flag, 0 means not done, 1 means done, -1 means error
short               wrapper_objsnf_dlsym_done          = 0; 
short               wrapper_objsnf_alloc_init_pending  = 0;

enum ichnaea_state_s ichnaea_state = WRAPPER_INIT_NOT_STARTED;

// Alloc Wrappers
void*        (*wrapper_objsnf_real_malloc)         (size_t)                  = NULL;
void*        (*wrapper_objsnf_real_realloc)        (void*, size_t)           = NULL;
void*        (*wrapper_objsnf_real_calloc)         (size_t, size_t)          = NULL;
void*        (*wrapper_objsnf_real_aligned_alloc)  (size_t, size_t)          = NULL;
void*        (*wrapper_objsnf_real_memalign)       (size_t, size_t)          = NULL;
int          (*wrapper_objsnf_posix_memalign)      (void **, size_t, size_t) = NULL;
void*        (*wrapper_objsnf_real_valloc)         (size_t)                  = NULL;
void         (*wrapper_objsnf_real_free)           (void*)                   = NULL;

// libc-syscall wrappers
ssize_t      (*wrapper_objsnf_real_read)           (int, void *, size_t)     = NULL;
ssize_t      (*wrapper_objsnf_real_readv)          (int, const struct iovec *, int) = NULL;
ssize_t      (*wrapper_objsnf_real_recv)           (int, void *, size_t, int) = NULL;
ssize_t      (*wrapper_objsnf_real_recvmsg)        (int, struct msghdr *, int) = NULL;
ssize_t      (*wrapper_objsnf_real_recvfrom)       (int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
ssize_t      (*wrapper_objsnf_real_pread)          (int, void *, size_t, off_t) = NULL;
ssize_t      (*wrapper_objsnf_real_pread64)        (int, void *, size_t, off64_t) = NULL;
size_t       (*wrapper_objsnf_real_fread)          (void *, size_t, size_t, FILE *) = NULL;
size_t       (*wrapper_objsnf_real_fread_unlocked) (void *, size_t, size_t, FILE *) = NULL;

ssize_t      (*wrapper_objsnf_real_write)          (int fildes, const void* buf, size_t nbyte) = NULL;

/* Load original allocation routines at first use */
__attribute__((constructor)) void alloc_init(void) {

    if (ichnaea_state != WRAPPER_INIT_NOT_STARTED) return; // Already initialized or in the process of initializing
    ichnaea_state = WRAPPER_INIT_STARTED;

    #if PRINT_STATE_INFO
    WRITE_STR_LIT( MAGENTA "Wrapper:" RESET" Initializing wrappers...\n" );
    #endif
    // Alloc* functions
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_malloc          =   dlsym(RTLD_NEXT, "malloc");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_realloc         =   dlsym(RTLD_NEXT, "realloc");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_calloc          =   dlsym(RTLD_NEXT, "calloc");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_aligned_alloc   =   dlsym(RTLD_NEXT, "aligned_alloc");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_memalign        =   dlsym(RTLD_NEXT, "memalign");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_valloc          =   dlsym(RTLD_NEXT, "valloc");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_posix_memalign       =   dlsym(RTLD_NEXT, "posix_memalign");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_free            =   dlsym(RTLD_NEXT, "free");

    // If any of the alloc functions are NULL, then we have a problem
    if ( !wrapper_objsnf_real_malloc || !wrapper_objsnf_real_realloc || !wrapper_objsnf_real_calloc || 
        !wrapper_objsnf_real_aligned_alloc || !wrapper_objsnf_real_memalign || !wrapper_objsnf_real_valloc ||
        !wrapper_objsnf_posix_memalign || !wrapper_objsnf_real_free ) {
        #if PRINT_STATE_INFO 
        WRITE_STR_LIT( RED "Wrapper:" RESET" Hooking *allocs: "RED "Failed\n" RESET);
        #endif
        wrapper_objsnf_dlsym_done = -1; // Error
        exit(1);
    } else {
        #if PRINT_STATE_INFO 
            WRITE_STR_LIT( MAGENTA "Wrapper:" RESET" Hooking *allocs: "GREEN "Success\n" RESET);
        #endif
    }

    ichnaea_state = WRAPPER_ALLOC_INIT_DONE; // Allocs are good to go




    // libcsyscall wrappers
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_read                          = dlsym(RTLD_NEXT, "read");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_readv                         = dlsym(RTLD_NEXT, "readv");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_recv                          = dlsym(RTLD_NEXT, "recv");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_recvmsg                       = dlsym(RTLD_NEXT, "recvmsg");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_recvfrom                      = dlsym(RTLD_NEXT, "recvfrom");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_pread                         = dlsym(RTLD_NEXT, "pread");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_pread64                       = dlsym(RTLD_NEXT, "pread64");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_fread                         = dlsym(RTLD_NEXT, "fread");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_fread_unlocked                = dlsym(RTLD_NEXT, "fread_unlocked");
    #pragma GCC diagnostic ignored "-Wpedantic"
    wrapper_objsnf_real_write                         = dlsym(RTLD_NEXT, "write");

    ichnaea_state = WRAPPER_WAITING_ON_TRACER; // Wrapper is good to go, just waiting on the tracer to be initialized
    
}

// __attribute__((destructor)) void alloc_fini(void) {
//     // If the tracer is already exiting or has exited, then don't do anything
//     if (ichnaea_state == EXITING) return;

//     // Switch pkey for all threads to start writing again
//     if (objsnf_gvars.pkey != -1) {
//         if ( pkey_set(objsnf_gvars.pkey , 0x0) == -1 ) {
//             perror("pkey_set@" AT_LINE);
//             exit(1);
//         }
//     }

//     ichnaea_state = EXITING;

//     #if PRINT_STATE_INFO
//     WRITE_STR_LIT( MAGENTA "Wrapper:" RESET" DESTRUCTOR CALLED...\n" );
//     #endif
// }


/* Util functions */
void wrapper_objsnf_unlock_all_objs_or_one(void * single_address) {
  
  if (ichnaea_state == WRAPPER_INIT_NOT_STARTED) alloc_init();
  if (ichnaea_state < WRAPPER_ACTIVE) return; // Don't unlock anything if the tracer is not active yet

  #if OBJSNF_ENABLE_PKEY_BASED_LOCK
    (void) (single_address);
    // If pkey based locking is enabled, then
    // we just enable write for THIS thread so the systemcall can proceed
    
    if (objsnf_gvars.pkey == -1) {
        WRITE_STR_LIT( TRACER_PRMPT "Wrapper,\n\t have you try adding objsnf_register_object((void *)0x55, 0,0,0) at the start of main()?" RESET "\n");
        exit(1);
    }



    if ( pkey_set(objsnf_gvars.pkey , 0x0) == -1 ) {
        WRITE_STR_LIT( RED "pkey_set@" RESET AT_LINE);
        perror("pkey_set");
        exit(1);
    }

  
  return;
  #else

  if (single_address != NULL) {
    // Check if the address is in the traced objects
    objsnf_traced_objects_s * obj = objsnf_address_within_traced_objects_pg(single_address, objsnf_gvars.traced_objects);

    if (obj != NULL) {
        if (mprotect(obj->addr, obj->size, PROT_READ | PROT_WRITE) == -1) {
            WRITE_STR_LIT(RED "mprotect@" RESET AT_LINE );
            return;
        }
        #if PRINT_STATE_INFO
        char const_str[500] = {0};
        snprintf(const_str, sizeof(const_str), MAGENTA "Wrapper:" RESET" Unlocking object %p of size %lu\n", obj->addr, obj->size);
        WRITE_STR_LIT(const_str);
        #endif
        objsnf_log_event(obj, false, false , NULL);
    }
  }

  
  else {
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(RED MAGENTA "Wrapper:" RESET" Unlocking all objects\n" RESET);
    #endif
    for (int i = 0; i < MAX_OBJ_COUNT; i++) {
          if (objsnf_gvars.traced_objects[i].addr == NULL) break;
          if (mprotect(
                objsnf_gvars.traced_objects[i].addr,
                objsnf_gvars.traced_objects[i].size,
                PROT_READ | PROT_WRITE
            ) == -1) {
              WRITE_STR_LIT( RED "mprotect@ " RESET AT_LINE);
              return;
          }
      }
  }

  
  return;
  #endif
}

// After we're done with the syscall, we need to lock the objects again
void wrapper_objsnf_lock_all_objs_or_none(void * single_address) {

    // Implimenting this for systems calls like write (read-data-from-userspace will be very annoying)
    bool is_read = false; // TODO: Open this can of worms later by passing this info from the syscall wrappers

  if (ichnaea_state == WRAPPER_INIT_NOT_STARTED) alloc_init();
  if (ichnaea_state < WRAPPER_ACTIVE) return; // Don't unlock anything if the tracer is not active yet
  

  #if OBJSNF_ENABLE_PKEY_BASED_LOCK
  // If pkey based locking is enabled, then 
  // we just enable write for THIS thread so the systemcall can proceed
  if ( pkey_set(objsnf_gvars.pkey , PKEY_DISABLE_WRITE) == -1 ) {
      WRITE_STR_LIT( RED "pkey_set@" RESET AT_LINE);
      exit(1);
  }

  // Log all objects incase of single address or all addresses 
  // TODO: Improve this to use hashing later to not log all objects but the only the ones that have changed)
  if (single_address != NULL) {
      objsnf_traced_objects_s * obj = objsnf_address_within_traced_objects_pg(single_address, objsnf_gvars.traced_objects);
      if (obj != NULL) {
          objsnf_log_event(obj, false, is_read, NULL);
      }
  }
  else {
    for (int i = 0; i < MAX_OBJ_COUNT; i++) {
        if (objsnf_gvars.traced_objects[i].addr == NULL) break;
        objsnf_log_event(&objsnf_gvars.traced_objects[i], true   , is_read, NULL);  
    }
  }

  return;
  #else
  
  if (single_address != NULL) {
      // Check if the address is in the traced objects
      #if PRINT_STATE_INFO
      WRITE_STR_LIT(RED MAGENTA "Wrapper:" RESET" Locking single objects\n" RESET);
      #endif
      objsnf_traced_objects_s * obj = objsnf_address_within_traced_objects_pg(single_address, objsnf_gvars.traced_objects);
      if (obj != NULL) {
          if (mprotect(obj->addr, obj->size, PROT_READ) == -1) {
              WRITE_STR_LIT( RED "mprotect@" RESET AT_LINE);
              return;
          }
          objsnf_log_event(obj, false , false, NULL);
      }
  }
  else {
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(MAGENTA "Wrapper:" RESET" Locking all objects\n");
    #endif
      for (int i = 0; i < MAX_OBJ_COUNT; i++) {
          if (objsnf_gvars.traced_objects[i].addr == NULL) {
              break;
          }
          int l = mprotect(objsnf_gvars.traced_objects[i].addr, objsnf_gvars.traced_objects[i].size, PROT_READ);
          if (l == -1) {
              WRITE_STR_LIT( RED "mprotect@" RESET AT_LINE);
              return;
          }
          objsnf_log_event(&objsnf_gvars.traced_objects[i], true ,false, NULL);
      }
  }
  return;
  #endif
}

