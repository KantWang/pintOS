#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"

#include "threads/flags.h"
#include "threads/synch.h"
#include "threads/init.h" 
#include "filesys/filesys.h"
#include "filesys/file.h" 
#include "userprog/gdt.h"
#include "intrinsic.h"

#define	STDIN_FILENO	0
#define	STDOUT_FILENO	1

#define MAX_FD_NUM	(1<<9)
void check_address(void *addr);
int add_file_to_fd_table(struct file *file);
struct file *fd_to_struct_filep(int fd);
void remove_file_from_fd_table(int fd);

void halt (void);
void exit (int);
void close (int fd);
bool create (const char *file , unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
int filesize(int fd);

void seek(int fd, unsigned position);
unsigned tell (int fd);

// int exec(char *file_name);
// pid_t fork (const char *thread_name, struct intr_frame *f);

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

struct lock filesys_lock;

void
syscall_init (void) {
	// printf("syscall_init 시작\n");
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	/* project02. system call */
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int sys_number = f->R.rax; // 

	switch(sys_number) {
		case SYS_HALT:
			halt();
		case SYS_EXIT:
			exit(f->R.rdi); // rdi: first argument
			break;
		// case SYS_FORK:
		// 	fork(f->R.rdi); 		
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi); // rsi: second argument
			break;
		case SYS_REMOVE:
			remove(f->R.rdi);		
			break;
		case SYS_OPEN:
			open(f->R.rdi);		
			break;
		case SYS_FILESIZE:
			filesize(f->R.rdi);
			break;
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx); // rdx: third argument
			break;
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);		
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rdx);		
			break;
		case SYS_TELL:
			tell(f->R.rdi);		
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
		default:
			thread_exit();
	}

	// printf ("system call!\n");
	// thread_exit ();
}

void check_address(void *addr) {
	struct thread *t = thread_current();
	// user 영역의 주소가 아니거나, 주소가 없거나, 페이지로 할당하지 않은 영역일 경우
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL)
		exit(-1); // 현재 프로세스 종료
}

/* pintOS 종료 */
void halt(void) {
	power_off();
}

/* 현재 프로세스 종료 */
void exit(int status) {
	struct thread *t = thread_current();
	t->exit_status = status;

	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

/* 파일 생성 */
bool create (const char *file, unsigned initial_size) {
	check_address(file);

	if (filesys_create(file, initial_size)) 
		return true;
	else 
		return false;
}

/* 파일 제거 */
bool remove(const char *file) {
	check_address(file);
	if (filesys_remove(file))
		return true;
	else
		return false;
}

int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	struct file *fileobj = fd_to_struct_filep(fd);
	int read_count;

	lock_acquire(&filesys_lock);

	if (fd == STDIN_FILENO) { // STDOUT인 경우
		lock_release(&filesys_lock);
		return -1;
	}
	else if (fd == STDOUT_FILENO) { // STDIN인 경우
		putbuf(buffer, size);
		read_count = size;
	}
	else if (fd >= 2) { // STDIN, STDOUT 외의 경우
		if (fileobj == NULL) { // 찾는 파일이 없으면
			lock_release(&filesys_lock);
			exit(-1); // 종료
		}
		read_count = file_write(fileobj, buffer, size);
	}

	lock_release(&filesys_lock);
	return read_count;
}

int open (const char *file) {
	check_address(file);
	struct file *file_obj = filesys_open(file);

	if (file_obj == NULL)
		return -1;

	int fd = add_file_to_fd_table(file_obj);

	if (fd == -1)
		file_close(file_obj);
	
	return fd;
}

int add_file_to_fd_table(struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx;

	while (t->file_descriptor_table[fd] != NULL && fd < FDCOUNT_LIMIT)
		fd++;
	
	if (fd >= FDCOUNT_LIMIT)
		return -1;

	t->fdidx = fd;
	fdt[fd] = file;
	return fd;
}

struct file *fd_to_struct_filep(int fd) {
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	
	struct file *file = fdt[fd];
	return file;	
}

int filesize(int fd) {
	struct file *fileobj = fd_to_struct_filep(fd);
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	if (fileobj == NULL)
		return -1;

	file_length(fileobj);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	check_address(buffer + size - 1);
	unsigned char *buf = buffer;
	int read_count; 

	struct file *fileobj = fd_to_struct_filep(fd);

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	if (fileobj == NULL)
		return -1;

	/* STDIN인 경우 */
	if (fd == STDIN_FILENO) {
		char key;
		for (int read_count = 0; read_count < size; read_count++) {
			key = input_getc();
			*buf++ = key;
			if (key == '\0')
				break;
		}
	}
	/* STDOUT인 경우: -1 반환 */
	else if (fd == STDOUT_FILENO)
		return -1;
	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(fileobj, buffer, size); // file read하는 동안 lock
		lock_release(&filesys_lock);
	}
	return read_count;
}

void seek (int fd, unsigned position) {
	if (fd < 2)
		return;
	
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);

	if (file == NULL)
		return;
	
	file_seek(file, position);
}

unsigned tell (int fd) {
	if (fd < 2)
		return;

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;
	
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	if (file == NULL)
		return;
	
	return file_tell(fd);
}

void close (int fd) {
	if (fd < 2)
		return;
	
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	
	if (file == NULL)
		return;
	
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	thread_current()->file_descriptor_table[fd] = NULL;
}