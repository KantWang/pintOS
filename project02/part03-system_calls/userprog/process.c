#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
struct thread *get_child_with_pid(int pid);

static bool setup_stack (struct intr_frame *if_);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	// printf("process_create_initd 진입, file_name: %s\n", file_name);
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* project02. command line parsing */
	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);

	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
	// printf("initd 진입!\n");
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/* 여기서 name은 유저 name, if_도 유저 스택 */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	/* project02. system call */
	struct thread *parent = thread_current();
	// 현재 thread의 parent_if에 if_를 저장
	// printf("	1. parent_if: %p\n", parent->parent_if);
	memcpy(&parent->parent_if, if_, sizeof(struct intr_frame));
	// printf("	2. parent_if: %p\n", parent->parent_if);

	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, parent); // 여기서 child_list에 자식의 elem 추가됨

	if (tid == TID_ERROR)
		return TID_ERROR;
	
	struct thread *child = get_child_with_pid(tid); // child thread를 찾고
	sema_down(&child->fork_sema); // 자식이 메모리에 load 될 때까지 blocked
	if (child->exit_status == -1)
		return TID_ERROR;

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/*  */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if is_kernel_vaddr(va)
		return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL)
		return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	// newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

struct MapElem
{
	/* key - parent's struct file */
	uintptr_t key;
	/* value - child's newly created struct file */
	uintptr_t value;
};

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) { // 부모 스레드가 인자로 들어옴. 부모의 것들을 자식에게 모두 복사해서 메모리에 올림
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current (); // 자식 스레드
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;

	/* process_fork에서 복사 해두었던 intr_frame */
	parent_if = &parent->parent_if;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame)); // if_에 parent_if를 복사
	if_.R.rax = 0; // if_의 R.rax 레지스터를 0으로 초기화(?)

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current); // tss를 업데이트. 자식 스레드 주소를 인자로 넣어준다
	/*
		void
		tss_update (struct thread *next) {
			ASSERT (tss != NULL);
			tss->rsp0 = (uint64_t) next + PGSIZE; // tss->rsp0에 자식주소 + PGSIZE를 저장
												  // 즉,
		}
	*/
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if (parent->fdidx == FDCOUNT_LIMIT)
		goto error;

	/* Project2-extra) multiple fds sharing same file - use associative map 
	(e.g. dict, hashmap) to duplicate these relationships
	other test-cases like multi-oom don't need this feature */
	const int MAPLEN = 10; 
	struct MapElem map[10];

	/* index for filling map */ 
	int dupCount = 0;
	
	current->file_descriptor_table[0] = parent->file_descriptor_table[0];
	current->file_descriptor_table[1] = parent->file_descriptor_table[1];

	for (int i = 2; i < FDCOUNT_LIMIT; i++) {
		struct file *file = parent->file_descriptor_table[i];
		if (file == NULL)
			continue;
		
		/* Project2-extra) linear search on key-pair array
		If 'file' is already duplicated in child, don't duplicate again but share it */
		bool found = false;
		for (int j = 0; j < MAPLEN; j++) {
			if (map[j].key == file) {
				found = true;
				current->file_descriptor_table[i] = map[j].value;
				break;
			}
		}
		if (!found) {
			struct file *new_file;
			if (file > 2)
				new_file = file_duplicate(file);
			else
				new_file = file;
			
			current->file_descriptor_table[i] = new_file;
			// if (dupCount < MAPLEN) {
			// 	map[dupCount].key = file;
			// 	map[dupCount++].value = new_file;
			// }
		}
	}
		
	current->fdidx = parent->fdidx;
	sema_up(&current->fork_sema); 
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);

	// if_.R.rax = 0;	
	// process_init();

error:
	current->exit_status = TID_ERROR;
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
	// thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	// printf("process_exec 진입, f_name: %s\n", f_name);
	// f_name: child-args childarg
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if; // 커널 스택 영역에 저장되겠지
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	char *argv[30];
	int argc = 0;

	char *token, *save_ptr;
	token = strtok_r(file_name, " ", &save_ptr); // " "를 기준으로 한 단어씩 return
	while (token != NULL) {
		argv[argc] = token;
		token = strtok_r(NULL, " ", &save_ptr);
		/* If S is null, start from saved position. */
		argc++;
	}

	/* And then load the binary */
	// 이때 file_name은 공백이 '\0'으로 치환되어 있음
	success = load (file_name, &_if); 
	

	/* If load failed, quit. */
	if (!success){
		palloc_free_page (file_name);
		return -1;
	}

	argument_stack(argv, argc, &_if);

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true); // stack에 잘 쌓였는지 보는 코드

	/* Start switched process. */
	// printf("do_iret 시작\n");
	// 여기까지 kernel mode
	do_iret (&_if); // do_iret 후 user mode
	// printf("do_iret 완료\n");
	NOT_REACHED ();
}

/* project02. command line parsing */
void argument_stack(char **argv, int argc, struct intr_frame *if_) {
	// printf("argument_stack 진입\n");
	char *arg_address[128];
	int argc_len;

	for (int i = argc-1; i> -1; i--) { 
		argc_len = strlen(argv[i]);
		if_->rsp = if_->rsp - (argc_len + 1);
		memcpy(if_->rsp, argv[i], argc_len+1); // null 공간까지 메모리에 cpy
		arg_address[i] = if_->rsp;
	}

	while (if_->rsp % 8 != 0) {
		if_->rsp = if_->rsp -1;
		// memset(if_->rsp, 0, sizeof(uint8_t));
		*(uint8_t *)if_->rsp = 0;
	}

	for (int j = argc; j > -1; j--) {
		if_->rsp = if_->rsp - 8;
		if (j == argc) {
			memset(if_->rsp, 0, sizeof(char **));
		} else {
			memcpy(if_->rsp, &arg_address[j], sizeof(char **));
		}
	}

	if_->R.rsi = if_->rsp;
	if_->R.rdi = argc;

	if_->rsp -= 8;
	memset(if_->rsp, 0, sizeof(void *));
	// if_->rsp = if_->rsp - 8;
	// memset(if_->rsp, 0, sizeof(void *));
	
	// if_->R.rdi = argc;
	// if_->R.rsi = if_->rsp + 8;
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// while (1){}
	// for (int i = 0; i < 100000000; i++);

	struct thread *child = get_child_with_pid(child_tid);

	if (child == NULL)
		return -1;

	/* 자식 프로세스가 종료할때 까지 대기 */
	sema_down(&child->wait_sema);

	/* 자식으로 부터 종료인자를 전달 받고 리스트에서 삭제 */
	int exit_status = child->exit_status;
	list_remove(&child->child_elem);

	/* 자식 프로세스 종료 상태인자 받은 후 자식 프로세스 종료하게 함 */
	sema_up(&child->free_sema);

	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	// P2-4 CLose all opened files	
	for (int i = 0; i < FDCOUNT_LIMIT; i++)
	{
		close(i);
	}

	/* thread_create에서 할당한 페이지 할당 해제 */
	palloc_free_multiple(curr->file_descriptor_table, FDT_PAGES); 

	/* 현재 프로세스가 실행중인 파일 종료 */
	file_close(curr->running);

	/* 현재 프로세스의 자원 반납 */
	process_cleanup ();

	/* 부모 프로세스가 자식 프로세스의 종료상태 확인하게 함 */
	sema_up(&curr->wait_sema);
	
	/* 부모 프로세스가 자식 프로세스 종료인자 받을때 까지 대기 */
	sema_down(&curr->free_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
/*
	ELF(Executable and Linkable Format)
	실행 파일, 목적 파일, 공유 라이브러리 그리고 코어 덤프를 위한 표준 파일 형식
	파일의 구성을 나타내는 로드맵과 같은 역할

	각 ELF 파일은 하나의 ELF 헤더와 파일 데이터로 이루어진다. 파일 데이터는 다음을 포함한다.
	-	0개 또는 그 이상의 세그먼트들을 정의하는 프로그램 헤더 테이블
	-	0개 또는 그 이상의 섹션들을 정의하는 섹션 헤더 테이블
	-	프로그램 헤더 테이블 또는 섹션 헤더 테이블의 엔트리들에 의해 참조되는 데이터

	e_version	오리지날 버전의 ELF인 경우 1로 설정된다.
	e_entry		이것은 엔트리 포인트의 메모리 주소이다. 
	        	즉 프로세스가 어디서 실행을 시작하는지를 말해준다. 
				이 필드는 위에서 정의한 32비트 또는 64비트에 따라 길이가 다르다.
	e_phoff		프로그램 헤더 테이블의 시작을 가리킨다.
	e_shoff		섹션 헤더 테이블의 시작을 가리킨다.
	e_flags		대상 아키텍처에 따라 이 필드의 해석이 달라진다.
	e_ehsize	이 헤더의 크기를 가지며 일반적으로 64비트의 경우 64바이트,
				32비트의 경우 52바이트이다.
	e_phentsize	프로그램 헤더 테이블 엔트리의 크기를 갖는다.
	e_phnum		프로그램 헤더 테이블에서 엔트리의 개수.
	e_shentsize	섹션 헤더 테이블 엔트리의 크기를 갖는다.
	e_shnum		섹션 헤더 테이블에서 엔트리의 개수.
	e_shstrndx	섹션 이름들을 포함하는 섹션 헤더 테이블 엔트리의 인덱스.
*/
#define Phdr ELF64_PHDR
/*
	ELF에는 여러 개의 Segment들이 존재하며 각 Segment들에 대한 정보를 가지고 있는 녀석이 있음. 그게 Program Header

	Segment란? 
	-	동일한 메모리 속성(read-only, writable, ...)을 가진 하나 또는 그 이상의 섹션의 집합
*/

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	// printf("load 진입, file_name: %s\n", file_name);
	// file_name: child-args
	// file_name == "child-args\0childarg\0"이기 때문에 위와 같이 print 찍힘
	struct thread *t = thread_current ();
	struct ELF ehdr; // ehdr에 open한 file의 elf header 정보를 저장
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ()); /* 까볼 것 */

	/* Open executable file. */
	file = filesys_open (file_name);
	// printf("	filesys_open 완료, file: %d\n", file);
	// file: 69476440 <-- fd. thread의 file_descriptor_table에 저장됨

	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	t->running = file; // 프로세스가 현재 실행중인 파일
	// 이렇게 스레드가 file을 가리키고 있으니까 load에서 file에 다 때려박으면 되는거구나

	/* 오픈된 파일은 디스크에 쓰기 금지. 파일 닫을 때 변경사항 업데이트 */
	// 왜 못쓰게 되는지 확인하자.
	// 타고 타고 들어가보면 inode->deny_write_cnt == 0이어야 write가 가능하게 되어있음
	// 그런데 file_deny_write에서 inode->deny_write_cnt++해줌.
	// file_allow_write(file) 될 때까지 쓰기 금지.
	file_deny_write(file);

	/* Read and verify executable header. */
	// file_read로 ehdr에 file의 elf header 정보 저장
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff; // 프로그램 헤더 테이블의 시작. 첫번째 프로그램 헤더의 주소이기도 하니까.. 첫번째 세그먼트의 주소
	for (i = 0; i < ehdr.e_phnum; i++) { // 모든 프로그램 헤더 탐색
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file)) // 프로그램 헤더 테이블의 모든 원소 확인 완료
			goto done;
		file_seek (file, file_ofs); 
		/* 
			위에서 file_ofs를 프로그램 헤더 테이블의 시작으로 변경했으니 file->pos = ehdr.e_phoff 즉, 첫번째 세그먼트로 file->pos 변경
			이후 과정은 당연하게도 다음 세그먼트로 pos 변경 계속하겠지
			모든 세그먼트를 loading 해야하니 당연히 이렇다
		*/
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr; // 그르치
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable)) // 그르치. 모든 세그먼트 로드. 어디에? file에.
						goto done;
				}
				else
					goto done;
				break;
		}
	}
	/* 이 위까지 완료되면서 HDD에서 메모리로의 loading이 끝났다 */

	/* Set up stack. */
	/* 까볼 것 */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO); // PAL_USER이므로 user_pool에.
												   // PAL_ZERO이므로 0으로 초기화.
	if (kpage != NULL) {
		
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true); // writable == true이므로 pte가 없으면 create
		if (success)
			if_->rsp = USER_STACK; // 스택 포인터 설정
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
/* 
	사용자 가상 주소 UPAGE에서 커널 가상 주소 KPAGE로의 매핑을 페이지 테이블에 추가합니다. WRITABLE이 true이면 사용자 프로세스가 페이지를 수정할 수 있습니다. 그렇지 않으면 읽기 전용입니다. UPAGE는 이미 매핑되어 있지 않아야 합니다. KPAGE는 아마도 palloc_get_page()를 사용하여 사용자 풀에서 얻은 페이지여야 합니다. 성공하면 true, UPAGE가 이미 매핑되어 있거나 메모리 할당에 실패하면 false를 반환합니다. 
*/
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	/* 
		upage를 kpage에 매핑한 후 t의 페이지 테이블에 추가 
		당연히 upage가 가리키는 곳에 이미 페이지가 할당되어 있으면 안된다	
	*/
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

struct thread *get_child_with_pid(int pid) {
	struct thread *cur = thread_current();
	struct list *child_list = &cur->child_list;

#ifdef DEBUG_WAIT
	printf("\nparent children # : %d\n", list_size(child_list));
#endif

	for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == pid)
			return t;
	}	
	return NULL;
}