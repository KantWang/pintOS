#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_address(void *addr);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* file을 읽을 때 다른 프로세스의 접근 차단 */
struct lock filesys_lock;
int dup2(int oldfd, int newfd);

#endif /* userprog/syscall.h */
