#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init(void);

/* 파일 사용시 lock하여 상호배제 구현
 * Read, Write 시 파일에 대한 동시접근이 일어날 수 있으므로 Lock 사용
 */
struct lock file_rw_lock;

#endif /* userprog/syscall.h */