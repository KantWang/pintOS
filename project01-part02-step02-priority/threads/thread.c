#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* 모든 thread를 관리하는 list */
// static struct list all_list;

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
/* ready 상태의 thread를 관리하는 list */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* 재워야 하는 스레드를 sleep list(block상태)에 넣어줌 */
static struct list sleep_list;

/* Statistics. */
static long long idle_ticks;    		/* # of timer ticks spent idle. */
static long long kernel_ticks;  		/* # of timer ticks in kernel threads. */
static long long user_ticks;    		/* # of timer ticks in user programs. */
// static long long wakeup_tick;   		/* 해당 쓰레드가 깨어나야 할 tick을 저장할 필드 */
// static long long next_tick_to_awake;    /* sleep_list에서 대기 중인 스레드들의 wakeup_tick값 중 최소값을 저장 */
static uint64_t next_tick_to_awake;    /* sleep_list에서 대기 중인 스레드들의 wakeup_tick값 중 최소값을 저장 */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. 각각의 스레드가 주도권을 잡는 시간 */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/************ 프로젝트 1 *************/

/* Thread를 blocked 상태로 만들고 sleep queue에 삽입하여 대기 */
void thread_sleep (int64_t ticks);

/* Sleep queue에서 깨워야 할 thread를 찾아서 wake */
void thread_awake (int64_t ticks);

/* sleep_list에서 대기 중인 Thread들의 wakeup_tick 값에서 최소 틱을 가진 스레드 저장 */
void update_next_tick_to_awake (int64_t ticks);

/* thread.c의 next_tick_to_awake 반환 */
int64_t get_next_tick_to_awake (void);

/* 현재 수행중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링 */
void test_max_priority (void);

/* 인자로 주어진 스레드들의 우선순위를 비교 */
bool cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

/*************************************/

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);		// THREAD_READY 상태로 된 스레드를 담고 있는 리스트
	list_init (&destruction_req);	
	list_init (&sleep_list);		// 재워야 하는 스레드를 담고 있는 리스트 (block 상태)
	next_tick_to_awake = INT64_MAX; // 나중에 update_next_tick_to_awake() 에서 next_tick_to_awake에 최솟값을 계속 갱신해줘야 하므로 max값으로 일단 초기화해둠

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick. (4 ticks)
   Thus, this function runs in an external interrupt context. (must disable interrupt)*/
void
thread_tick (void) { // test 결과로 보이는 수치가 계산되는 곳 Thread: 550 idle ticks, 62 kernel ticks, 0 user ticks
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	/* thread_ticks가 4 tick 넘으면 다음 스레드에 CPU 주도권을 넘김 */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */

/* 
새로 추가된 thread가 실행 중인 thread보다 우선순위가 높은 경우 CPU를 선점
하도록 하기 위해 thread_create() 함수 수정
새로운 thread가 생성되면 ready_list에 thread를 추가
 */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority); // 
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);

	/* 현재 실행중인 thread와 우선순위를 비교하여, 새로 생성된
	   thread의 우선순위가 높다면 thread_yield()를 통해 CPU를 양보 */
	if (thread_current()->priority < t->priority) {
		thread_yield();
	}

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
/*
alarm clock 
block 상태의 스레드를 깨우고 난 뒤 ready list의 맨 뒤에 삽입한다
*/
/*
priority schedule
ready_list를 우선순위로 정렬
ready_list에 thread가 추가됨
*/
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED); // blocked 상태여야
	// 우선순위 순으로 정렬되어 ready_list에 삽입되어야
	// list_less_func *less;
	list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
	// list_push_back (&ready_list, &t->elem); // ready_list의 맨 뒤로 넣어줌
	t->status = THREAD_READY; // ready 상태로 갱신
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING); // 현재 스레드를 THREAD_DYING 상태로 status 바꿔줌
	NOT_REACHED ();
}

/************ busy waiting **********/
/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
/* 현재 (running 중인) 스레드를 비활성화 시키고, 
   깨어날 시간이 아니면 ready_list에 삽입한다. */
// void
// thread_yield (void) {
// 	struct thread *curr = thread_current ();
// 	enum intr_level old_level;

// 	ASSERT (!intr_context ());

// 	old_level = intr_disable (); // 인터럽트 정지시키고 이전 인터럽트의 상태 반환
// 	if (curr != idle_thread)
// 		list_push_back (&ready_list, &curr->elem); // 해당 스레드를 ready list의 맨 뒤로 넣어줌
// 	do_schedule (THREAD_READY);	// running인 스레드의 status를 ready로 바꿈
// 	intr_set_level (old_level); // 이전 인터럽트의 상태로 복구
// }
/*************************************/

/************ 프로젝트 1 *************/
/* priority scheduling */
/* 현재 수행 중인 스레드가 사용 중인 CPU를 양보 */
/* 현재 thread가 CPU를 양보하여 
   ready_list에 삽입 될 때 우선순위 순서로 정렬되어
   삽입 되도록 수정
 */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable (); // 인터럽트 정지시키고 이전 인터럽트의 상태 반환
	if (curr != idle_thread) {
		// 우선순위 순으로 정렬되어 ready_list에 삽입되어야
		// list_less_func *less;
		list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL);
		// list_push_back (&ready_list, &curr->elem); // 해당 스레드를 ready list의 맨 뒤로 넣어줌
	}
	do_schedule (THREAD_READY);	// running인 스레드의 status를 ready로 바꿈
	intr_set_level (old_level); // 이전 인터럽트의 상태로 복구
}

/*************************************/

/************ 프로젝트 1 *************/

/* Thread를 sleep list에 삽입하고 blocked 상태로 만들어 대기 */
void
thread_sleep (int64_t ticks) { // 현재 시간 tick + 재우고 싶은 시간
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	// ASSERT (!intr_context ());

	old_level = intr_disable ();  // 인터럽트 정지시키고 이전 인터럽트의 상태 반환

	ASSERT(curr != idle_thread);
	curr->wakeup_tick = ticks; // wakeup_tick(깨어나야 하는 ticks 값) : 현재 tick + 재우고 싶은 시간 
	// if (curr != idle_thread){
	update_next_tick_to_awake(curr->wakeup_tick);
	list_push_back (&sleep_list, &curr->elem); // 해당 스레드를 sleep list의 맨 뒤로 넣어줌
	thread_block();
	// }
	intr_set_level (old_level); // 이전 인터럽트의 상태로 복구
}

/* sleep list에서 깨워야 할 thread를 찾아서 wake 하고 ready list의 맨 뒤에 넣어줌 */
void 
thread_awake (int64_t ticks) { // 현재 시간 ticks
	struct list_elem *address = list_begin(&sleep_list);
	struct list_elem *e;
	for (e = address; e != list_end(&sleep_list);){
		struct thread *t = list_entry(e, struct thread, elem);
		if (t->wakeup_tick <= ticks) {
			e = list_remove(&t->elem); // sleep_list에서 삭제해주고, next 포인터가 return되어 e에 담김
			thread_unblock(t);		   // THREAD_BLOCKED를 THREAD_READY 상태로 만들어주고 ready list 맨 뒤로 넣어줌
		}
		else {
			e = list_next(e);
			update_next_tick_to_awake(t->wakeup_tick); 
			// sleep_list에 남아 있는 스레드의 wakeup_tick 중 무엇이 최솟값인지 계속 갱신 및 저장해주기 위한 코드
			// 이미 sleep_list에 남아 있지 않은 스레드(awake된 스레드)는 최솟값으로 갱신해줄 필요가 없음

			// 깨우지 못했으므로 다시 재워주는 거나 마찬가지 (block 상태로 유지) 
			// timer_interrupt에서 awake 시키려고 할 때 
			// 계속 block 상태로 잠재워둔 스레드의 wakeup tick이 최솟값일 수도 있으므로 update를 시켜주는 것
		}
	}
}

/* Thread들이 가진 wakeup_tick 값에서 "최소 값"을 갱신 및 저장 */
void update_next_tick_to_awake (int64_t ticks) { // wakeup_tick : 재우고 싶은 시간 + 그 당시 현재 ticks 
	next_tick_to_awake = (next_tick_to_awake > ticks) ? ticks : next_tick_to_awake;
}

/* 최소 tick값을 반환 */
int64_t get_next_tick_to_awake (void) {
	return next_tick_to_awake;
}

/* Sets the current thread's priority to NEW_PRIORITY. */
/* 현재 수행중인 스레드의 우선순위를 new_priority로 변경 */
/* 현재 쓰레드의 우선 순위와 ready_list에서 가장 높은 우선 순위를 비교하여
   스케쥴링 하는 함수 호출 */
void
thread_set_priority (int new_priority) {
	thread_current()->priority = new_priority;
	test_max_priority();

	// struct list_elem *r = list_begin(&ready_list);
	// struct list_elem *e;
	// for (e = r; e != list_end(&ready_list);){
	// 	struct thread *t = list_entry(e, struct thread, elem);
	// 	if (t->priority > )
	// }
	// list_less_func *cmp_priority;

	// struct list_elem *max_ready_priority = list_max(&ready_list, cmp_priority, NULL);
	// struct thread *t = list_entry(max_ready_priority, struct thread, elem);

	// if (t->priority > thread_current()->priority) {
	// 	do_schedule (THREAD_READY);  // 확신이 없음 schedule()?
	// }

}

/* 현재 수행중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링 */
void 
test_max_priority (void) {
	if (list_empty(&ready_list)){
		return;
	}
	// list_less_func *less;
	// struct list_elem *max_ready_priority = list_max(&ready_list, cmp_priority, NULL);
	struct list_elem *max_ready_priority = list_front(&ready_list);
	struct thread *t = list_entry(max_ready_priority, struct thread, elem);

	if (t->priority > thread_current()->priority) {
		thread_yield();
	}

}

/* 인자로 주어진 스레드들의 우선순위를 비교 */
// ?
bool 
cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	// if (!list_insert_ordered(a, b, NULL)) {
	// 	return 1;
	// } else {
	// 	return 0;
	// }
	struct thread *one = list_entry(a, struct thread, elem);
	struct thread *two = list_entry(b, struct thread, elem);
	int answer;
	answer = (one->priority > two->priority) ? 1 : 0;

	return answer;
}

/*************************************/

/* Returns the current thread's priority. */
/* 현재 thread의 우선순위를 반환 */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
/*
ready list에서 맨 앞 스레드를 pop해 CPU 주도권을 넘겨줄 다음 스레드로 설정한다.
만약 ready list가 비어 있다면 idle 스레드가 다음 CPU 주도권을 잡도록 설정해준다.
*/
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
/* 다음 스레드로 전환되는 것 */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */

// 새 스레드의 페이지 테이블을 활성화하여 스레드를 전환하고 이전 스레드가 소멸되는 경우 스레드를 삭제합니다.
// 이 함수의 호출 시, 우리는 방금 스레드 PREV에서 전환했고, 새로운 스레드는 이미 실행 중이며, 인터럽트는 여전히 비활성화되어 있다.
// 스레드 스위치가 완료될 때까지 printf()를 호출하는 것은 안전하지 않습니다. 실제로 이는 기능 끝에 printf()s를 추가해야 한다는 것을 의미한다.
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	// 먼저 전체 실행 컨텍스트를 intr_frame으로 복원한 다음 do_iret을 호출하여 다음 스레드로 전환합니다. 
	// 전환이 완료될 때까지 여기서 스택을 사용하지 마십시오.
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
/* 현재 (running중인) 스레드를 status로 바꾸고, 새로운 스레드를 실행한다.  */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);				 // 인터럽트 해제되어 있어야
	ASSERT (thread_current()->status == THREAD_RUNNING); // 현재 running 중인 스레드의 상태를 status로 바꿔주기 위해 THREAD_RUNNING 상태여야
	while (!list_empty (&destruction_req)) { 			 // 지금 yield하려는 스레드와 상관이 없고, thread_exit()으로 destruction_req 리스트에 있는 스레드들 (삭제 리스트) 
		struct thread *victim =							 // schedule()로 새로운 스레드에 할당시키기 전에 메모리 확보를 위해 시행
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);						 // victim 페이지 해제
	}	
	thread_current ()->status = status;					 // 현재 running 중인 스레드의 상태를 status로 바꿔줌
	schedule ();										 // 다음 ready list의 스레드(만약 스레드가 비어 있으면 idle 스레드)를 RUNNING 상태로 하고 CPU 주도권을 넘겨줌
}

// 다음 ready list의 스레드(만약 스레드가 비어 있으면 idle 스레드)를 RUNNING 상태로
// 만들어주고 CPU 주도권을 넘겨준다(thread_launch).
static void
schedule (void) {
	struct thread *curr = running_thread ();			 // running 중인 스레드 - 아직 CPU 주도권 가지고 있음 (running의 의미 : CPU 주도권을 가지고 있느냐 없느냐)
	struct thread *next = next_thread_to_run ();		 // CPU 주도권을 넘겨받고 다음에 run될 스레드
 
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);			 // curr 스레드의 status는 do_schedule()에서 status로 바뀌었으므로 THREAD_RUNNING이 아니어야
	ASSERT (is_thread (next));							 // 다음 스레드가 valid한 스레드여야
	/* Mark us as running. */
	next->status = THREAD_RUNNING;						 // 다음 스레드의 status를 THREAD_RUNNING으로

	/* Start new time slice. */
	thread_ticks = 0;									 // 새로운 스레드가 CPU의 주도권을 잡아야 하므로 그 이후로 thread_ticks를 새로 0으로 초기화

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {	// 하나의 스레드만 있지 않을 때, 즉 idle_thread가 아닐 때 
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free request here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) { // 아직 CPU의 주도권은 원래 thread한테 있는데, 이것의 status가 THREAD_DYING으로 do_schedule()에서 설정되었으면
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);	// thread_exit() 에서 스레드를 destroy하고 싶었으므로 destruction_req 리스트에 현재 스레드의 elem를 넣어줌
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		/* next 스레드로 스레드를 전환시키고자 아직 주도권을 잡고 있는 스레드의 
		   information을 저장하고 다음 스레드로 전환해줌
		 */
		thread_launch (next); // palloc_free_page(victim)를 do_schedule()에서 해주는 이유는 현재 스레드가 사라지면 안되기 때문. 현재 스레드의 next 값을 가져와야 하므로 일단은 살려둠
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}