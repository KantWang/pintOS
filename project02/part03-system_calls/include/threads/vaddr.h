#ifndef THREADS_VADDR_H
#define THREADS_VADDR_H

#include <debug.h>
#include <stdint.h>
#include <stdbool.h>

#include "threads/loader.h"

/* Functions and macros for working with virtual addresses.
 *
 * See pte.h for functions and macros specifically for x86
 * hardware page tables. */

#define BITMASK(SHIFT, CNT) (((1ul << (CNT)) - 1) << (SHIFT))

/* Page offset (bits 0:12). */
#define PGSHIFT 0                          /* Index of first offset bit. */
#define PGBITS  12                         /* Number of offset bits. */
#define PGSIZE  (1 << PGBITS)              /* Bytes in a page. */
#define PGMASK  BITMASK(PGSHIFT, PGBITS)   /* Page offset bits (0:12). */

/* Offset within a page. */
#define pg_ofs(va) ((uint64_t) (va) & PGMASK)

#define pg_no(va) ((uint64_t) (va) >> PGBITS)

/* Round up to nearest page boundary. */
#define pg_round_up(va) ((void *) (((uint64_t) (va) + PGSIZE - 1) & ~PGMASK))

/* Round down to nearest page boundary. */
#define pg_round_down(va) (void *) ((uint64_t) (va) & ~PGMASK)

/* Kernel virtual address start */
// 1 << 40 정도의 사이즈 같다
// KERN_BASE == 549,822,922,752
// 2^39      == 549,755,813,888
// -   ------------------------
//                   67,108,864 == 2^26 == 64MB
// 커널 시작은 2^39보다 64MB 위에서 한다
// 2^39면 40비트..
// 64비트 시스템이면 남은 비트가 24개?
// 커널을 24개의 비트로 표현하니까
// 그 사이즈는 2^24 == 16MB. 맞나?
#define KERN_BASE LOADER_KERN_BASE // 1 << 40 정도 사이즈

/* User stack start */
// USER_STACK == 1,195,900,928
// 2^30       == 1,073,741,824
// -   -----------------------
//                 122,159,104
// 				   134,217,728 == 2^27 = 128MB
// 유저스택은 2^30보다 128MB 가량 더 위에 있다?
#define USER_STACK 0x47480000

/* Returns true if VADDR is a user virtual address. */
// 커널 영역의 주소값이 아니면 유저 영역의 주소이다
#define is_user_vaddr(vaddr) (!is_kernel_vaddr((vaddr)))

/* Returns true if VADDR is a kernel virtual address. */
#define is_kernel_vaddr(vaddr) ((uint64_t)(vaddr) >= KERN_BASE)

// FIXME: add checking
/* Returns kernel virtual address at which physical address PADDR
 *  is mapped. */
#define ptov(paddr) ((void *) (((uint64_t) paddr) + KERN_BASE))

/* Returns physical address at which kernel virtual address VADDR
 * is mapped. */
#define vtop(vaddr) \
({ \
	ASSERT(is_kernel_vaddr(vaddr)); \
	((uint64_t) (vaddr) - (uint64_t) KERN_BASE);\
})

#endif /* threads/vaddr.h */
