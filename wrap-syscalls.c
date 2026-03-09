#include "wrapper.h"

#include <sys/socket.h>

ssize_t read(int fd, void *buf, size_t nbytes)  {
  // WRITE_STR_LIT( "Wrapper:"" read() called\n");
  // This could be called by the interrupt handler so lets make it use the notmal read if ichnaea_smart_alloc_lock is set
  if (ichnaea_smart_alloc_lock) return wrapper_objsnf_real_read(fd, buf, nbytes);

  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str) - 1, MAGENTA "Wrapper:" RESET" Captured: read(%d, %p, %ld)\n\r" , fd, buf, nbytes);
  WRITE_STR_LIT(const_str);
  #endif

  void * pg_aligned = (void *)(((uintptr_t)buf) & ~(PAGE_SIZE - 1));

  wrapper_objsnf_unlock_all_objs_or_one(pg_aligned);
  size_t rtn =  wrapper_objsnf_real_read(fd, buf, nbytes);
  int saved_errno = errno;
  wrapper_objsnf_lock_all_objs_or_none(pg_aligned);

  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" read returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif
  errno = saved_errno;
  return rtn;
}

// Write wrapper
// This is exclusively for tracing buffer reads
ssize_t write(int fildes, const void* buf, size_t nbyte) {

  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: write(%d, %p, %ld)\n" , fildes, buf, nbyte);
  WRITE_STR_LIT(const_str);
  #endif
  void * pg_aligned = (void *)(((uintptr_t)buf) & ~(PAGE_SIZE - 1));

  wrapper_objsnf_unlock_all_objs_or_one(pg_aligned);
  ssize_t rtn = wrapper_objsnf_real_write(fildes, buf, nbyte);

  // Print the error and filename
  if (rtn == -1) {
      #if !DISABLE_CRITICAL_LOGGING
      #define SHELL_RED "\033[0;31m"
      #define SHELL_RESET "\033[0m"

      fprintf(stderr, SHELL_RED "[Error]" SHELL_RESET " write() syscall failed in wrapper with error: %s\n", strerror(errno));
      #endif
  }


  int saved_errno = errno;

  #if !OBJSNF_ENABLE_PKEY_BASED_LOCK && ICHNAEA_TRACE_READS
  printf("Wrapper: write() isn't supported without PKEY based locking yet\n");
  exit(1);
  #endif


  // Match the object's address and log the event as a read
  objsnf_traced_objects_s * obj = objsnf_address_within_traced_objects_pg(pg_aligned, objsnf_gvars.traced_objects);

  if (obj != NULL) objsnf_log_event(obj, false, true , NULL);

  if ( pkey_set(objsnf_gvars.pkey , PKEY_DISABLE_ACCESS) == -1 ) {
      // WRITE_STR_LIT( RED "pkey_set@" RESET AT_LINE);
      // exit(1);
  }


  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" write returned %ld\n" , rtn);
  WRITE_STR_LIT(_const_str);
  #endif
  errno = saved_errno;
  return rtn;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
  // WRITE_STR_LIT( "Wrapper:"" readv() called\n");
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: readv(%d, %d)\n" , fd, iovcnt);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_readv(fd, iov, iovcnt);
  int saved_errno = errno;
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" readv returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif
  errno = saved_errno;
  return rtn;
}

ssize_t recv(int sockfd, void * buf, size_t size, int flags) {
  
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: recv(%d, %p, %ld, %d)\n\r" , sockfd, buf, size, flags);
  WRITE_STR_LIT(const_str);

  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_recv(sockfd, buf, size, flags);
  wrapper_objsnf_lock_all_objs_or_none(NULL);

  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" recv returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);

  return rtn;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: recvmsg(%d, -- , %d)\n" , sockfd, flags);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_recvmsg(sockfd, msg, flags);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(_const_str),  MAGENTA "Wrapper:" RESET" recvmsg returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

ssize_t recvfrom(int sockfd, void *restrict buf, size_t size, int flags, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: recvfrom(%d, %p, %ld, %d, %p, %p)\n" , sockfd, buf, size, flags, (void *) addr, (void *)addrlen);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_recvfrom(sockfd, buf, size, flags, addr, addrlen);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" recvfrom returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}
#pragma GCC diagnostic ignored "-Wunused-parameter"
ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset) {
  // WRITE_STR_LIT( "Wrapper:"" pread() called\n");
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: pread(%d, %p, %ld, %ld)\n" , fd, buf, nbytes, offset);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_read(fd, buf, nbytes);
  int saved_errno = errno;
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" pread returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif
  errno = saved_errno;
  return rtn;
}

#pragma GCC diagnostic ignored "-Wunused-parameter"
ssize_t pread64(int fd, void *buf, size_t nbytes, off64_t offset) {
  // WRITE_STR_LIT( "Wrapper:"" pread64() called\n");
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: pread64(%d, %p, %ld, %ld)\n" , fd, buf, nbytes, offset);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_read(fd, buf, nbytes);
  int saved_errno = errno;
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" pread64 returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif
  errno = saved_errno;

  return rtn;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  // WRITE_STR_LIT( "Wrapper:"" fread() called\n");
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: fread(%p, %ld, %ld, %p)\n" , ptr, size, nmemb, (void *)stream);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(ptr);
  size_t rtn = wrapper_objsnf_real_fread(ptr, size, nmemb, stream);
  int saved_errno = errno;
  wrapper_objsnf_lock_all_objs_or_none(ptr);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(_const_str),  MAGENTA "Wrapper:" RESET" fread returned %ld\n" , rtn);
  WRITE_STR_LIT(_const_str);
  #endif
  errno = saved_errno;
  return rtn;
}

size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  // WRITE_STR_LIT( "Wrapper:"" fread_unlocked() called\n");
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "Wrapper:" RESET" Captured: fread_unlocked(%p, %ld, %ld, %p)\n" , ptr, size, nmemb, (void *) stream);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);   

  size_t rtn = wrapper_objsnf_real_read(fileno(stream), ptr, size * nmemb);
  int saved_errno = errno;
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(_const_str),  MAGENTA "Wrapper:" RESET" fread_unlocked returned %ld\n" , rtn);
  WRITE_STR_LIT(_const_str);
  #endif
  errno = saved_errno;
  return rtn;
}
