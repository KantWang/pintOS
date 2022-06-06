#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"

#include "threads/flags.h"
#include "threads/synch.h"
#include "threads/init.h" 
#include "filesys/filesys.h"
#include "filesys/file.h" 
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "intrinsic.h"

#define	STDIN_FILENO	0
#define	STDOUT_FILENO	1

const int STDIN = 1;
const int STDOUT = 2;

#define MAX_FD_NUM	(1<<9) // 2**10, 0~1023개의 FD
void check_address(void *addr);
static struct file *find_file_by_fd(int fd);
int add_file_to_fd_table(struct file *file);
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
pid_t fork (const char *thread_name, struct intr_frame *f);

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
    /*
    	함수 return 값에 대한 x86-64 convention은 이 값을 rax레지스터에 배치하는 것이다.
	    값을 반환하는 system call은 struct int_frame의 rax 멤버를 수정함으로써 convention을 지킨다.
    */
	switch (f->R.rax) // rax는 system call number이다.
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1)
				exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		// case SYS_DUP2:
		// 	f->R.rax = dup2(f->R.rdi, f->R.rsi);
		// 	break;
		default:
			exit(-1);
			break;
	}

	// printf ("system call!\n");
	// thread_exit ();
}

/*************************************************************
** ------------------- helper function -------------------- **
*************************************************************/

/* 사용할 수 있는 주소인지 확인하는 함수. 사용 불가 시 -1 종료 */
void check_address(void *addr) {
	struct thread *t = thread_current();
	// user 영역의 주소가 아니거나, 주소가 없거나, 페이지로 할당하지 않은 영역일 경우
	if (!(is_user_vaddr(addr)) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL)
		exit(-1); // 현재 프로세스 종료
}

/* 파일 디스크립터로 파일 검색 하여 파일 구조체 반환 */
static struct file *find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid id
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	
	return cur->file_descriptor_table[fd];	
}

/* 새로 만든 파일을 파일 디스크립터 테이블에 추가 */
int add_file_to_fd_table(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->file_descriptor_table;	// file descriptor table

	// Project2-extra - (multi-oom) Find open spot from the front
	/* 0 ~ 511 범위를 탐색. fdt가 비어 있으면 while문 탈출. fdidx는 빈 곳을 가리킨다 */
	while (cur->fdidx < FDCOUNT_LIMIT && fdt[cur->fdidx])
		cur->fdidx++;

	// Error - fdt full
	if (cur->fdidx >= FDCOUNT_LIMIT)
		return -1;

	fdt[cur->fdidx] = file;
	return cur->fdidx;
}

/* 파일 테이블에서 fd 제거 */
void remove_file_from_fd_table(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->file_descriptor_table[fd] = NULL;
}

/*************************************************************
** --------------------- system call ---------------------- **
*************************************************************/

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
	return filesys_create(file, initial_size);
}

/* 파일 제거 */
bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int read_count;

	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
		
	struct thread *curr = thread_current();

	lock_acquire(&filesys_lock);

	if (fd == STDIN_FILENO) { // STDOUT인 경우
		lock_release(&filesys_lock);
		return -1;
	}
	else if (fd == STDOUT_FILENO) { // STDIN인 경우
		putbuf(buffer, size);
		read_count = size;
		// if (curr->stdout_count == 0) {
		// 	NOT_REACHED();
		// 	remove_file_from_fd_table(fd);
		// 	read_count = -1;
		// }
		// else {
		// 	putbuf(buffer, size);
		// 	read_count = size;
		// }
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
	struct file *open_file = filesys_open(file);

	if (open_file == NULL)
		return -1;

	int fd = add_file_to_fd_table(open_file);

	if (fd == -1)
		file_close(open_file);
	
	return fd;
}

// 파일이 열려 있다면 Byte 반환
int filesize(int fd) {
	struct file *open_file = find_file_by_fd(fd);
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	if (open_file == NULL)
		return -1;

	return file_length(open_file);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	off_t read_byte;
	struct thread *cur = thread_current();
	struct file *read_file = find_file_by_fd(fd);

	uint8_t *read_buffer = buffer;
	// if (fd < 0 || fd >= FDCOUNT_LIMIT)
	// 	return;

	if (read_file == NULL)
		return -1;

	/* STDIN인 경우 */
	if (read_file == STDIN_FILENO) {
		if (cur->stdin_count == 0) {
			NOT_REACHED();
			remove_file_from_fd_table(fd);
			read_byte = -1;
		}
		else {
			char key;
			for (read_byte = 0; read_byte < size; read_byte++)
			{
				key = input_getc();
				*read_buffer++ = key;
				if (key == '\0')
					break;
			}
		}
    }
	/* STDOUT인 경우: -1 반환 */
	else if (fd == STDOUT_FILENO)
		return -1;
	else {
        lock_acquire(&filesys_lock);
        read_byte = file_read(read_file, buffer, size);
        lock_release(&filesys_lock);
    }
    return read_byte;
}

void seek (int fd, unsigned position) {	
	struct file *seek_file = find_file_by_fd(fd);

	if (seek_file <= 2)
		return;
	
	seek_file->pos = position;
}

/* 파일의 시작점부터 현재 위치까지의 offset을 반환 */
unsigned tell (int fd) {	
	struct file *tell_file = find_file_by_fd(fd);
	if (tell_file <= 2)
		return;

	return file_tell(tell_file);
}

/* fd로 file을 찾아서 fd table에서 지워버리는 함수 */
void close (int fd) {	
	// printf("	close\n");
	struct file *close_file = find_file_by_fd(fd);
	
	if (close_file == NULL)
		return;

	struct thread *cur = thread_current();

	// if (fd == 0 || close_file == STDIN_FILENO)
	// 	cur->stdin_count--;	
	// else if (fd == 1 || close_file == STDOUT_FILENO)
	// 	cur->stdout_count--;
	
	remove_file_from_fd_table(fd);

	if (fd <= 1 || close_file <= 2)
		return;
	
	// if (close_file -> dupCount == 0)
	// 	file_close(close_file);
	// else
	// 	close_file->dupCount--;

}

pid_t fork (const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

// Kernel command line: -q -f put args-single run 'args-single onearg'
// Kernel command line: -q -f put exec-arg put child-args run exec-arg
// 명령이 위와 같은데 file_name에 왜 "child-args childarg"가 들어오는거지?
int exec(char *file_name) {
	check_address(file_name);
	// printf("	file_name: %s\n", file_name);
	// file_name: child-simple
	// file_name: child-args childarg

	int size = strlen(file_name) + 1;
	// printf("	size: %d\n", size);
	// size: 13
	// size: 20
	char *fn_copy = palloc_get_page(PAL_ZERO); // 0으로 초기화 된 페이지 1개 획득

	if(fn_copy == NULL)
		exit(-1);
	strlcpy(fn_copy, file_name, size);
	/*
		strlcpy(목적지, 값이 들어있는 곳의 주소, 복사할 사이즈 + 1 --> \0 포함해야 해서)
	*/

	// 현재 실행 컨텍스트를 fn_copy로 변경
	if (process_exec(fn_copy) == -1)
		return -1;

	/* Caller 프로세스는 do_iret() 후 돌아오지 못한다. */
	NOT_REACHED();
	return 0; //이 값은 리턴되지 않는다. 즉, exec()은 오직 에러가 발생했을 때만 리턴한다.
}

int dup2(int oldfd, int newfd) {
	struct file *file_fd = find_file_by_fd(oldfd);

	if (file_fd == NULL)
		return -1;
	
	if (oldfd == newfd)
		return newfd;
	
	struct thread *cur = thread_current();
	struct file **fdt = cur->file_descriptor_table;

	if (file_fd == STDIN_FILENO)
		cur->stdin_count++;
	else if (file_fd == STDOUT_FILENO)
		cur->stdout_count++;
	else
		file_fd->dupCount++;

	close(newfd);
	fdt[newfd] = file_fd;
	return newfd;
}