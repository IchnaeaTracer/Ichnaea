#define _OBJSNF_SRC
#define _GNU_SOURCE
#define _WRAP_PRELOAD_H
#include <execinfo.h>
#include <errno.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <capstone/capstone.h>

#include "tracer.h"

// Alloc Wrapper Prototypes
extern void*        (*wrapper_objsnf_real_malloc)         (size_t)                  ;
extern void*        (*wrapper_objsnf_real_realloc)        (void*, size_t)           ;
extern void*        (*wrapper_objsnf_real_calloc)         (size_t, size_t)          ;
extern void*        (*wrapper_objsnf_real_aligned_alloc)  (size_t, size_t)          ;
extern void*        (*wrapper_objsnf_real_memalign)       (size_t, size_t)          ;
extern int          (*wrapper_objsnf_posix_memalign)      (void **, size_t, size_t) ;
extern void*        (*wrapper_objsnf_real_valloc)         (size_t)                  ;
extern void         (*wrapper_objsnf_real_free)           (void*)                   ;


extern void         alloc_init(void); // Forward declaration for the alloc_init function

// libc-syscall wrappers TODO: Add more wrappers as needed
extern ssize_t      (*wrapper_objsnf_real_read)           (int, void *, size_t)     ;
extern ssize_t      (*wrapper_objsnf_real_readv)          (int, const struct iovec *, int) ;
extern ssize_t      (*wrapper_objsnf_real_recv)           (int, void *, size_t, int) ;
extern ssize_t      (*wrapper_objsnf_real_recvmsg)        (int, struct msghdr *, int) ;
extern ssize_t      (*wrapper_objsnf_real_recvfrom)       (int, void *, size_t, int, struct sockaddr *, socklen_t *) ;
extern ssize_t      (*wrapper_objsnf_real_pread)          (int, void *, size_t, off_t) ;
extern ssize_t      (*wrapper_objsnf_real_pread64)        (int, void *, size_t, off64_t) ;
extern size_t       (*wrapper_objsnf_real_fread)          (void *, size_t, size_t, FILE *) ;
extern size_t       (*wrapper_objsnf_real_fread_unlocked) (void *, size_t, size_t, FILE *) ;


// Local Prototypes
extern void  wrapper_objsnf_unlock_all_objs_or_one  (void * single_address);
extern void  wrapper_objsnf_lock_all_objs_or_none   (void * single_address);

// Some Random declarations to make the compiler happy
extern int snprintf (char *__restrict __s, size_t __maxlen, const char *__restrict __format, ...);
extern void exit(int status);
typedef unsigned long uintptr_t;

typedef struct zalloc_obj {
    size_t size;
    void *ptr;
} zalloc_obj;


extern short                        wrapper_objsnf_dlsym_done; 
extern short                          wrapper_objsnf_alloc_init_pending;
extern objsnf_safe_globals_t        objsnf_gvars;                              // Global variables from the tracer.c