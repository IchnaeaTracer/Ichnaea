#include "wrapper.h"


ssize_t read(int fd, void *buf, size_t nbytes)  {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str) - 1,  MAGENTA "wrap-preload:" RESET" Captured: read(%d, %p, %ld)\n" , fd, buf, nbytes);
  WRITE_STR_LIT(const_str);
  #endif

  void * pg_aligned = (void *)(((uintptr_t)buf) & ~(PAGE_SIZE - 1));

  wrapper_objsnf_unlock_all_objs_or_one(pg_aligned);
  size_t rtn =  wrapper_objsnf_real_read(fd, buf, nbytes);
  wrapper_objsnf_lock_all_objs_or_none(pg_aligned);

  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" read returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: readv(%d, %p, %d)\n" , fd, iov, iovcnt);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_readv(fd, iov, iovcnt);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" readv returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

ssize_t recv(int sockfd, void * buf, size_t size, int flags) {
  
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: recv(%d, %p, %ld, %d)\n" , sockfd, buf, size, flags);
  WRITE_STR_LIT(const_str);

  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_recv(sockfd, buf, size, flags);
  wrapper_objsnf_lock_all_objs_or_none(NULL);

  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" recv returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);

  return rtn;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: recvmsg(%d, %p, %d)\n" , sockfd, msg, flags);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_recvmsg(sockfd, msg, flags);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(_const_str),  MAGENTA "wrap-preload:" RESET" recvmsg returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

ssize_t recvfrom(int sockfd, void * buf, size_t size, int flags, struct sockaddr * addr, socklen_t * addrlen) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: recvfrom(%d, %p, %ld, %d, %p, %p)\n" , sockfd, buf, size, flags, addr, addrlen);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_recvfrom(sockfd, buf, size, flags, addr, addrlen);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" recvfrom returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: pread(%d, %p, %ld, %ld)\n" , fd, buf, nbytes, offset);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_read(fd, buf, nbytes);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" pread returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

ssize_t pread64(int fd, void *buf, size_t nbytes, off64_t offset) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: pread64(%d, %p, %ld, %ld)\n" , fd, buf, nbytes, offset);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  ssize_t rtn = wrapper_objsnf_real_read(fd, buf, nbytes);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" pread64 returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: fread(%p, %ld, %ld, %p)\n" , ptr, size, nmemb, stream);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  size_t rtn = wrapper_objsnf_real_read(fileno(stream), ptr, size * nmemb);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" fread returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}

size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  #if PRINT_STATE_INFO
  char const_str[500] = {0};
  snprintf(const_str, sizeof(const_str),  MAGENTA "wrap-preload:" RESET" Captured: fread_unlocked(%p, %ld, %ld, %p)\n" , ptr, size, nmemb, stream);
  WRITE_STR_LIT(const_str);
  #endif
  wrapper_objsnf_unlock_all_objs_or_one(NULL);
  size_t rtn = wrapper_objsnf_real_read(fileno(stream), ptr, size * nmemb);
  wrapper_objsnf_lock_all_objs_or_none(NULL);
  #if PRINT_STATE_INFO
  char _const_str[500] = {0};
  snprintf(_const_str, sizeof(_const_str),  MAGENTA "wrap-preload:" RESET" fread_unlocked returned %ld\n" , rtn);
  WRITE_STR_LIT(const_str);
  #endif

  return rtn;
}
