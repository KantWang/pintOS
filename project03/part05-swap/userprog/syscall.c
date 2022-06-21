#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "vm/vm.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* syscall functions */
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
int _write(int fd UNUSED, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(char *file_name);
int dup2(int oldfd, int newfd);
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

/* syscall helper functions */
void check_address(const uint64_t *addr);
static struct file *find_file_by_fd(int fd);
int add_file_to_fdt(struct file *file);
void remove_file_from_fdt(int fd);

/* Project2-extra */
const int STDIN = 1;
const int STDOUT = 2;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	// lock 초기화
	// 각 시스템 콜에서 lock 획득 후 시스템 콜 처리, 시스템 콜 완료 시 lock 반납
	lock_init(&file_rw_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	// printf("syscall! , %d\n",f->R.rax);
	thread_current()->rsp = f->rsp;
	switch (f->R.rax)
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
		/* buffer 사용 유무를 고려하여 유효성 검사를 하도록 코드 추가 */
		/* ------------------------------------------------------ */
		if (exec(f->R.rdi) == -1)
			exit(-1);
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		// rdi : argc,	rsi : argv
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		/* buffer 사용 유무를 고려하여 유효성 검사를 하도록 코드 추가 */
		// check_valid_buffer
		/* ------------------------------------------------------ */
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		/* buffer 사용 유무를 고려하여 유효성 검사를 하도록 코드 추가 */
		// check_valid_buffer
		/* ------------------------------------------------------ */
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		/* buffer 사용 유무를 고려하여 유효성 검사를 하도록 코드 추가 */
		// check_valid_buffer
		/* ------------------------------------------------------ */
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
	case SYS_DUP2:
		f->R.rax = dup2(f->R.rdi, f->R.rsi);
		break;
	/* project03 - mmap, munmap */
	case SYS_MMAP:
		f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
		break;
	case SYS_MUNMAP:
		munmap(f->R.rdi);
		break;
	default:
		exit(-1);
		break;
	}
}
/* ------------------- helper function -------------------- */

/* 사용할 수 있는 주소인지 확인하는 함수. 사용 불가 시 -1 종료 */
void check_address(const uint64_t *addr)
{
	// // printf("	addr: %p\n", addr);
	if (!is_user_vaddr(addr) || addr == NULL)
	{
		//// //printf("	### syscall check_address ###\n");
		exit(-1); // terminated
	}
	// struct thread *t = thread_current();
	// if (!is_user_vaddr(addr) || addr == NULL)
	// {
	// 	exit(-1); // terminated
	// }

}

/* find_file_by_fd()
 * 프로세스의 파일 디스크립터 테이블을 검색하여 파일 객체의 주소를 리턴
 * 파일 디스크립터로 파일 검색 하여 파일 구조체 반환
 */
static struct file *find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid id
	// 해당 테이블에 파일 객체가 없을 시 NULL 반환
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;

	return cur->fdTable[fd];
}
/* add_file_to_fdt()
 * 파일 객체에 대한 파일 디스크립터 생성
새로 만든 파일을 파일 디스크립터 테이블에 추가 */
int add_file_to_fdt(struct file *file)
{
	// 현재 스레드의 파일 디스크립터 테이블을 가져온다.
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable; // file descriptor table

	/* Project2 user programs
	 * 다음 File Descriptor 값 1 증가
	 * 최대로 열 수 있는 파일 제한(FDCOUNT_LIMIT)을 넘지 않고,
	 * 해당 fd에 이미 열려있는 파일이 있다면 1씩 증가한다.
	 */
	while (cur->fdIdx < FDCOUNT_LIMIT && fdt[cur->fdIdx])
		cur->fdIdx++;

	// Error - fdt full
	if (cur->fdIdx >= FDCOUNT_LIMIT)
		return -1;

	// 가용한 fd로 fdt[fd] 에 인자로 받은 file을 넣는다.
	fdt[cur->fdIdx] = file;
	// 추가된 파일 객체의 File Descriptor 반환
	return cur->fdIdx;
}
/* remove_file_from_fdt()
 * 파일 디스크립터에 해당하는 파일을 닫고 해당 엔트리 초기화
 * 파일 테이블에서 fd 제거
 */
void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fdTable[fd] = NULL;
}

/* ------------------------ syscall --------------------------*/

/* 핀토스 종료 */
void halt(void)
{
	power_off();
}

/* 현재 진행중인 스레드 종료. 종료 상태 메세지 출력 */
void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

/* 요청받은 파일을 생성한다. 만약 파일 주소가 유효하지 않다면 종료 */
bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	if (filesys_create(file, initial_size))
	{
		return true;
	}
	else
	{
		return false;
	}
}

/* 요청받은 파일이름의 파일을 제거 */
bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

/* 요청받은 파일을 open. 파일 디스크립터가 가득차있다면 다시 닫아준다. */
int open(const char *file)
{
	lock_acquire(&file_rw_lock);
	check_address(file);
	// 해당 파일의 이름으로 열고, 해당 파일의 객체를 리턴한다.
	struct file *fileobj = filesys_open(file);

	if (fileobj == NULL){
		// printf("	0621 fileobj == NUlL\n");
		lock_release(&file_rw_lock);
		return -1;
	}
	// 서로 만든  파일을 현재 스레드의 파일디스크립터 테이블에 추가하고 해당 fd를 리턴한다.
	int fd = add_file_to_fdt(fileobj);

	/* 파일 디스크립터가 가득찬 경우 */
	if (fd == -1){
		// printf("	0621 fd == -1\n");
		lock_release(&file_rw_lock);
		file_close(fileobj);
	}

	lock_release(&file_rw_lock);
	// 해당 파일의 디스크립터를 리턴
	return fd;
}

/* 주어진 파일을 실행한다. */
int exec(char *file_name)
{
	//printf("	@@@ exec file_name: %s @@@\n", file_name);
	check_address(file_name);

	int siz = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);

	if (!fn_copy)
		exit(-1);
	strlcpy(fn_copy, file_name, siz);

	if (process_exec(fn_copy) == -1)
		return -1;

	// Not reachable

	NOT_REACHED();

	return 0;
}

/* write()
 * 열린 파일의 데이터를 기록하는 시스템 콜
 * 버퍼에 있는 내용을 fd 파일에 작성. 파일에 작성한 바이트 반환
 * 성공 시 기록한 데이터의 바이트 수를 반환, 실패시 -1 반환
 * buffer : 기록할 데이터를 저장한 버퍼의 주소 값, size : 기록할 데이터의 크기
 * fd 값이 1일 때? 버퍼에 저장된 데이터를 화면에 출력 (putbuf() 이용)
 */
int write(int fd, const void *buffer, unsigned size)
{
	int ret = 0; // 기록한 데이터의 바이트 수, 실패시 -1

	struct file *fileobj = find_file_by_fd(fd); // 실패시 NULL 반환
	if (fileobj == NULL)
		return -1;

	struct thread *curr = thread_current();

	if (fileobj == STDOUT)
	{
		if (curr->stdout_count == 0)
		{
			// Not reachable
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else
		{
			/* 문자열(버퍼)을 화면(콘솔)에 출력해주는 함수 */
			putbuf(buffer, size);
			ret = size;
		}
	}
	else if (fileobj == STDIN)
	{
		ret = -1;
	}
	else
	{
		lock_acquire(&file_rw_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}

	return ret;
}

/* read()
 * 요청한 파일을 버퍼에 읽어온다. 읽어들인 바이트를 반환
 * 열린 파일의 데이터를 읽는 시스템 콜
 * 성공 시 읽은 바이트 수를 반환, 실패 시 -1 반환
 * buffet : 읽은 데이터를 저장한 버퍼의 주소 값, size : 읽을 데이터의 크기
 * fd 값이 0일 때? 키보드의 데이터를 읽어 버퍼에 저장 (input_getc() 이용)
 */
int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	struct page *p = spt_find_page(&thread_current()->spt, buffer);
	if (p != NULL && !(p->writable))
		exit(-1);

	// check_address(buffer + size - 1);
	int ret = 0;
	struct thread *cur = thread_current();

	struct file *fileobj = find_file_by_fd(fd);
	if (!fileobj)
		return -1;

	if (fileobj == STDIN) // 1
	{
		if (cur->stdin_count == 0)
		{
			// Not reachable
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else
		{
			int i;
			unsigned char *buf = buffer;

			/* 키보드로 적은(버퍼) 내용 받아옴 */
			for (i = 0; i < size; i++)
			{
				char c = input_getc();
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		}
	}
	else if (fileobj == STDOUT)
	{
		ret = -1;
	}
	else
	{
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}

	return ret;
}

void close(int fd)
{
	// 해당 fd가 가리키는 file객체를 가져온다.
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return;

	struct thread *cur = thread_current();

	/* fd가 0(stdin), 1(stdout)이면(닫으려는 파일이 표준입 or 출력을 가리키면)
	 * stdin_count과 stdout_count를 1 감소시킨다.
	 */
	if (fd == 0 || fileobj == STDIN)
	{
		cur->stdin_count--;
	}
	else if (fd == 1 || fileobj == STDOUT)
	{
		cur->stdout_count--;
	}

	// 현재 스레드의 fdt에서 fd를 가진 파일을 삭제한다.(=NULL)
	remove_file_from_fdt(fd);

	/*
	 * stdin과 stdout은 dupcount가 없으므로 그냥 리턴하지만,
	 * 해당 파일의 dupcount(refcnt)가 0이면 해당 파일의 객체를 인자로 파일을 닫는다.
	 */
	if (fd <= 1 || fileobj <= 2)
		return;

	if (fileobj->dupCount == 0)
		file_close(fileobj);
	else
		fileobj->dupCount--;
}

/* 파일이 열려있다면 바이트 반환, 없다면 -1 반환 */
int filesize(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

void seek(int fd, unsigned position)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	fileobj->pos = position;
}

/* 파일의 시작점부터 현재 위치까지의 offset을 반환 */
unsigned tell(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj <= 2)
		return;
	return file_tell(fileobj);
}

tid_t fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

/* dup2()
 * 식별자 테이블 엔트리의 이전 내용을 덮어써서 식별자 테이블 엔트리 oldfd를 newfd로 복사
 */
int dup2(int oldfd, int newfd)
{
	struct file *fileobj = find_file_by_fd(oldfd);

	// oldfd가 불분명하면 이 시스템 콜은 실패하며 -1을 리턴, newfd는 닫히지 않는다.

	//	oldfd가 명확하고 newfd가 oldfd와 같은 값을 가진다면, dup2() 함수는 실행되지 않고 newfd값을 그대로 반환한다.
	if (oldfd == newfd) // 만약 newfd가 이전에 열렸다면, 재사용하기 전에 자동으로 닫힌다.
		return newfd;

	if (fileobj == NULL)
		return -1;

	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;

	// Don't literally copy, but just increase its count and share the same struct file
	// [syscall close] Only close it when count == 0

	// Copy stdin or stdout to another fd
	if (fileobj == STDIN)
		cur->stdin_count++;
	else if (fileobj == STDOUT)
		cur->stdout_count++;
	else
		fileobj->dupCount++;

	close(newfd);
	fdt[newfd] = fileobj;
	return newfd;
}

bool verify_stack(void *sp) {
}

/* project03 - mmap, munmap */
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	struct file *file = find_file_by_fd(fd);
	
	if (length <= 0 || pg_ofs(addr) ||  addr == NULL || is_kernel_vaddr(addr) || fd == 0 || fd == 1 || !file || pg_ofs(offset))
		return NULL;

	return do_mmap(addr, length, writable, file, offset);
}

void munmap (void *addr) {
	//// //printf("	### munmap - addr: %p ###\n", addr);
	// printf("	munmap\n");
	// mmap_idx를 넣어줘야지 않을까
	do_munmap(addr);
}


// /* buffer를 사용하는 read() system call의 경우 buffer의 주소가 유효한 가상주소인지 아닌지 검사할 필요성이 있음
//  * buffer의 유효성을 검사하는 함수
//  * check_valid_buffer 구현시 check_address() 함수를 사용
//  * writable변수는 buffer에 내용을 쓸 수 있는지 없는지 검사하는 변수
//  */
// void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool writable)
// {
// 	/* 1. 인자로 받은 buffer로부터 buffer + size까지의 크기가 한 페이지의 크기를 넘을 수도 있음 */

// 	/* check_address를 이용해서 주소의 유저영역 여부를 검사함과 동시에 vm_entry 구조체를 얻음 */

// 	/* 해당 주소에 대한 vm_entry 존재여부와 vm_entry의 writable 멤버가 true인지 검사 */
// 	// is_writable()

// 	/* 위 내용을 buffer부터 buffer + size까지의 주소에 포함되는 vm_entry들에 대해 적용 */
// 	/* ------------------------- */
// }

// //buffer가 swap되지 않도록 pin해놓는 역할
// void pin_buffer (void *start, int size)
// {
// 	void *ptr;
// 	for (ptr=start; ptr < start+size; ptr += PGSIZE)
// 	{
// 		struct vm_entry *vme=find_vme(ptr);
// 		vme->pinned = true;
// 		if(!vme->is_loaded)
// 			handle_mm_fault(vme);
// 	}
// }
// //buffer를 pin해논 것을 다시 swap할 수 있도록 unpin하는 역할
// void unpin_buffer (void *start, int size)
// {
// 	void *ptr;
// 	for (ptr=start; ptr < start+size; ptr += PGSIZE)
// 	{
// 		struct vm_entry *vme=find_vme(ptr);
// 		vme->pinned = false;
// 	}
// }