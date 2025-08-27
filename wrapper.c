#include "wrapper.h"

// Dlsym stat flag, 0 means not done, 1 means done, -1 means error
short               wrapper_objsnf_dlsym_done          = 0; 
short               wrapper_objsnf_alloc_init_pending  = 0;


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

/* Load original allocation routines at first use */
void alloc_init(void) {

  wrapper_objsnf_alloc_init_pending = 1;
  #if PRINT_STATE_INFO
  WRITE_STR_LIT( MAGENTA "wrap-preload:" RESET" Hooking *allocs...\n" );
  #endif
  // Alloc* functions
  wrapper_objsnf_real_malloc      =   dlsym(RTLD_NEXT, "malloc");
  wrapper_objsnf_real_realloc     =   dlsym(RTLD_NEXT, "realloc");
  wrapper_objsnf_real_calloc      =   dlsym(RTLD_NEXT, "calloc");
  wrapper_objsnf_real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
  wrapper_objsnf_real_memalign    =   dlsym(RTLD_NEXT, "memalign");
  wrapper_objsnf_real_valloc      =   dlsym(RTLD_NEXT, "valloc");
  wrapper_objsnf_posix_memalign   =   dlsym(RTLD_NEXT, "posix_memalign");
  wrapper_objsnf_real_free        =   dlsym(RTLD_NEXT, "free");
  
  
  if (!wrapper_objsnf_real_malloc || !wrapper_objsnf_real_realloc || !wrapper_objsnf_real_calloc || !wrapper_objsnf_real_free ) {
    char const_str[500] = {0};
    
    snprintf(
      const_str,
      sizeof(const_str),
      "wrapper_objsnf_real_malloc: %p, wrapper_objsnf_real_realloc: %p, wrapper_objsnf_real_calloc: %p, wrapper_objsnf_real_free: %p\n", 
      (void*) wrapper_objsnf_real_malloc,
      (void*) wrapper_objsnf_real_realloc,
      (void*) wrapper_objsnf_real_calloc,
      (void*) wrapper_objsnf_real_free
    );

    WRITE_STR_LIT(const_str);
    WRITE_STR_LIT( MAGENTA "wrap-preload:" RESET" Hooking *allocs: "RED "Failed\n" RESET);
    exit(1);
  } 
  #if PRINT_STATE_INFO 
  else WRITE_STR_LIT( MAGENTA "wrap-preload:" RESET" Hooking *allocs: "GREEN "Success\n" RESET);
  #endif

  wrapper_objsnf_alloc_init_pending = 0;

  // libcsyscall wrappers
  wrapper_objsnf_real_read                          = dlsym(RTLD_NEXT, "read");
  wrapper_objsnf_real_readv                         = dlsym(RTLD_NEXT, "readv");
  wrapper_objsnf_real_recv                          = dlsym(RTLD_NEXT, "recv");
  wrapper_objsnf_real_recvmsg                       = dlsym(RTLD_NEXT, "recvmsg");
  wrapper_objsnf_real_recvfrom                      = dlsym(RTLD_NEXT, "recvfrom");
  wrapper_objsnf_real_pread                         = dlsym(RTLD_NEXT, "pread");
  wrapper_objsnf_real_pread64                       = dlsym(RTLD_NEXT, "pread64");
  wrapper_objsnf_real_fread                         = dlsym(RTLD_NEXT, "fread");
  wrapper_objsnf_real_fread_unlocked                = dlsym(RTLD_NEXT, "fread_unlocked");

  wrapper_objsnf_dlsym_done = -1; // we'll set this to 1 at tracer initialization time in tracer.c
}


/* Util functions */

void wrapper_objsnf_unlock_all_objs_or_one(void * single_address) {
  
  if (wrapper_objsnf_dlsym_done == 0) alloc_init();
  if (wrapper_objsnf_dlsym_done == -1) return;
  

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
        snprintf(const_str, sizeof(const_str), MAGENTA "wrap-preload:" RESET" Unlocking object %p of size %lu\n", obj->addr, obj->size);
        WRITE_STR_LIT(const_str);
        #endif
        objsnf_log_event(obj, false);
    }
  }

  
  else {
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(RED MAGENTA "wrap-preload:" RESET" Unlocking all objects\n" RESET);
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
}

// After we're done with the syscall, we need to lock the objects again
void wrapper_objsnf_lock_all_objs_or_none(void * single_address) {

  if (wrapper_objsnf_dlsym_done == 0) alloc_init();
  if (wrapper_objsnf_dlsym_done == -1) return;
  
  if (single_address != NULL) {
      // Check if the address is in the traced objects
      #if PRINT_STATE_INFO
      WRITE_STR_LIT(RED MAGENTA "wrap-preload:" RESET" Locking single objects\n" RESET);
      #endif
      objsnf_traced_objects_s * obj = objsnf_address_within_traced_objects_pg(single_address, objsnf_gvars.traced_objects);
      if (obj != NULL) {
          if (mprotect(obj->addr, obj->size, PROT_READ) == -1) {
              WRITE_STR_LIT( RED "mprotect@" RESET AT_LINE);
              return;
          }
          objsnf_log_event(obj, false);
      }
  }
  else {
    #if PRINT_STATE_INFO
    WRITE_STR_LIT(MAGENTA "wrap-preload:" RESET" Locking all objects\n");
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
          objsnf_log_event(&objsnf_gvars.traced_objects[i], true);
      }
  }
  return;
}

