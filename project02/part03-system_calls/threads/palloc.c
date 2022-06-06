#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/init.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* Page allocator.  Hands out memory in page-size (or
   page-multiple) chunks.  See malloc.h for an allocator that
   hands out smaller chunks.

   System memory is divided into two "pools" called the kernel
   and user pools.  The user pool is for user (virtual) memory
   pages, the kernel pool for everything else.  The idea here is
   that the kernel needs to have memory for its own operations
   even if user processes are swapping like mad.

   By default, half of system RAM is given to the kernel pool and
   half to the user pool.  That should be huge overkill for the
   kernel pool, but that's just fine for demonstration purposes. */

/* A memory pool. */
struct pool {
	struct lock lock;               /* Mutual exclusion. */
	struct bitmap *used_map;        /* Bitmap of free pages. */
	uint8_t *base;                  /* Base of pool. 1byte */
};

/* Two pools: one for kernel data, one for user pages. */
// 이렇게 전역으로 선언해 두고 bitmap
static struct pool kernel_pool, user_pool;

/* Maximum number of pages to put in user pool. */
size_t user_page_limit = SIZE_MAX;
static void
init_pool (struct pool *p, void **bm_base, uint64_t start, uint64_t end);

static bool page_from_pool (const struct pool *, void *page);

/* multiboot info */
struct multiboot_info {
	uint32_t flags;
	uint32_t mem_low;
	uint32_t mem_high;
	uint32_t __unused[8];
	uint32_t mmap_len;
	uint32_t mmap_base;
};

/* e820 entry */
struct e820_entry {
	uint32_t size;
	uint32_t mem_lo;
	uint32_t mem_hi;
	uint32_t len_lo;
	uint32_t len_hi;
	uint32_t type;
};

/* Represent the range information of the ext_mem/base_mem */
struct area {
	uint64_t start;
	uint64_t end;
	uint64_t size;
};

#define BASE_MEM_THRESHOLD 0x100000
#define USABLE 1
#define ACPI_RECLAIMABLE 3
#define APPEND_HILO(hi, lo) (((uint64_t) ((hi)) << 32) + (lo))

/* Iterate on the e820 entry, parse the range of basemem and extmem. */
static void
resolve_area_info (struct area *base_mem, struct area *ext_mem) {
	struct multiboot_info *mb_info = ptov (MULTIBOOT_INFO);
	struct e820_entry *entries = ptov (mb_info->mmap_base);
	uint32_t i;

	for (i = 0; i < mb_info->mmap_len / sizeof (struct e820_entry); i++) {
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE) {
			uint64_t start = APPEND_HILO (entry->mem_hi, entry->mem_lo);
			uint64_t size = APPEND_HILO (entry->len_hi, entry->len_lo);
			uint64_t end = start + size;
			printf("%llx ~ %llx %d\n", start, end, entry->type);

			struct area *area = start < BASE_MEM_THRESHOLD ? base_mem : ext_mem;

			// First entry that belong to this area.
			if (area->size == 0) {
				*area = (struct area) {
					.start = start,
					.end = end,
					.size = size,
				};
			} else {  // otherwise
				// Extend start
				if (area->start > start)
					area->start = start;
				// Extend end
				if (area->end < end)
					area->end = end;
				// Extend size
				area->size += size;
			}
		}
	}
}

/*
 * Populate the pool.
 * All the pages are manged by this allocator, even include code page.
 * Basically, give half of memory to kernel, half to user.
 * We push base_mem portion to the kernel as much as possible.
 */
static void
populate_pools (struct area *base_mem, struct area *ext_mem) {
	// printf("base_mem->size: %d, ext_mem->size: %d\n", base_mem->size, ext_mem->size);
	/*
		base_mem->size: 654336, ext_mem->size: 19791872
	*/
	extern char _end;
	void *free_start = pg_round_up (&_end);
	// printf("&_end: %p, free_start: %p\n", &_end, free_start);
	/* 
		&_end: 0x800422a8fc, free_start: 0x800422b000
	*/
	uint64_t total_pages = (base_mem->size + ext_mem->size) / PGSIZE;
	uint64_t user_pages = total_pages / 2 > user_page_limit ?
		user_page_limit : total_pages / 2;
	uint64_t kern_pages = total_pages - user_pages;
	// printf("total_pages: %d\nuser_pages: %d\nkern_pages: %d\n", total_pages, user_pages, kern_pages);
	/*
		total_pages: 4991 --> 20MB
		user_pages:  2495 --> 10MB
		kern_pages:  2496 --> 10MB
	*/
	// Parse E820 map to claim the memory region for each pool.
	enum { KERN_START, KERN, USER_START, USER } state = KERN_START;
	uint64_t rem = kern_pages;
	uint64_t region_start = 0, end = 0, start, size, size_in_pg;

	struct multiboot_info *mb_info = ptov (MULTIBOOT_INFO);
	struct e820_entry *entries = ptov (mb_info->mmap_base);

	uint32_t i;
	for (i = 0; i < mb_info->mmap_len / sizeof (struct e820_entry); i++) {
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE) {
			start = (uint64_t) ptov (APPEND_HILO (entry->mem_hi, entry->mem_lo));
			size = APPEND_HILO (entry->len_hi, entry->len_lo);
			end = start + size;
			size_in_pg = size / PGSIZE;

			if (state == KERN_START) {
				region_start = start;
				state = KERN;
			}

			switch (state) {
				case KERN:
					if (rem > size_in_pg) {
						rem -= size_in_pg;
						break;
					}
					// generate kernel pool
					
					init_pool (&kernel_pool,
							&free_start, region_start, start + rem * PGSIZE);
					// printf("&kernel_pool: %p\n&free_start: %p\nregion_start: %d\nstart: %d\nstart+rem*PGSIZE: %d\n", &kernel_pool, &free_start, region_start, start, start+rem*PGSIZE);
					/*
						&kernel_pool: 0x8004229c20
						&free_start:  0x8004000ec0
						region_start:     67108864
						start:            68157440
						start+rem*PGSIZE: 77729792
					*/
				// pml4_get_page(PAL_USER) --> user_pool
							// 2496 * 4KB == 9.75MB 만큼의 kernel pool 확보
					// Transition to the next state
					if (rem == size_in_pg) {
						rem = user_pages;
						state = USER_START;
					} else {
						region_start = start + rem * PGSIZE;
						rem = user_pages - size_in_pg + rem;
						state = USER;
					}
					break;
				case USER_START:
					region_start = start;
					state = USER;
					break;
				case USER:
					if (rem > size_in_pg) {
						rem -= size_in_pg;
						break;
					}
					ASSERT (rem == size);
					break;
				default:
					NOT_REACHED ();
			}
		}
	}

	// generate the user pool
	init_pool(&user_pool, &free_start, region_start, end);
	// printf("&user_pool: %p\n&free_start: %p\nregion_start: %d\nend: %d\n", &kernel_pool, &free_start, region_start, end);
	/*
		&user_pool:   0x8004229c20
		&free_start:  0x8004000ec0
		region_start: 77729792
		end:          87949312
	*/

	// Iterate over the e820_entry. Setup the usable.
	uint64_t usable_bound = (uint64_t) free_start;
	struct pool *pool;
	void *pool_end;
	size_t page_idx, page_cnt;

	for (i = 0; i < mb_info->mmap_len / sizeof (struct e820_entry); i++) {
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE) {
			uint64_t start = (uint64_t)
				ptov (APPEND_HILO (entry->mem_hi, entry->mem_lo));
			uint64_t size = APPEND_HILO (entry->len_hi, entry->len_lo);
			uint64_t end = start + size;

			// TODO: add 0x1000 ~ 0x200000, This is not a matter for now.
			// All the pages are unuable
			if (end < usable_bound)
				continue;

			start = (uint64_t)
				pg_round_up (start >= usable_bound ? start : usable_bound);
split:
			if (page_from_pool (&kernel_pool, (void *) start))
				pool = &kernel_pool;
			else if (page_from_pool (&user_pool, (void *) start))
				pool = &user_pool;
			else
				NOT_REACHED ();

			pool_end = pool->base + bitmap_size (pool->used_map) * PGSIZE;
			page_idx = pg_no (start) - pg_no (pool->base);
			if ((uint64_t) pool_end < end) {
				page_cnt = ((uint64_t) pool_end - start) / PGSIZE;
				bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
				start = (uint64_t) pool_end;
				goto split;
			} else {
				page_cnt = ((uint64_t) end - start) / PGSIZE;
				bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
			}
		}
	}
}

/* Initializes the page allocator and get the memory size */
uint64_t
palloc_init (void) {
	// printf("palloc_init 시작\n");
  /* End of the kernel as recorded by the linker.
     See kernel.lds.S. */
	/* 링커에 의해 기록된 커널의 끝 */
	extern char _end;
	struct area base_mem = { .size = 0 };
	struct area ext_mem = { .size = 0 };

	resolve_area_info (&base_mem, &ext_mem);
	printf ("Pintos booting with: \n");
	printf ("\tbase_mem: 0x%llx ~ 0x%llx (Usable: %'llu kB)\n",
		  base_mem.start, base_mem.end, base_mem.size / 1024);
	printf ("\text_mem: 0x%llx ~ 0x%llx (Usable: %'llu kB)\n",
		  ext_mem.start, ext_mem.end, ext_mem.size / 1024);
	populate_pools (&base_mem, &ext_mem);
	return ext_mem.end;
}

/* Obtains and returns a group of PAGE_CNT contiguous free pages.
   If PAL_USER is set, the pages are obtained from the user pool,
   otherwise from the kernel pool.  If PAL_ZERO is set in FLAGS,
   then the pages are filled with zeros.  If too few pages are
   available, returns a null pointer, unless PAL_ASSERT is set in
   FLAGS, in which case the kernel panics. */
/* page_cnt개의 연속 사용이 가능한 free 페이지를 획득 */
void *
palloc_get_multiple (enum palloc_flags flags, size_t page_cnt) {
	struct pool *pool = flags & PAL_USER ? &user_pool : &kernel_pool;

	lock_acquire (&pool->lock); // 디스크 IO 작업 중 충돌 발생하지 않도록 lock
	size_t page_idx = bitmap_scan_and_flip (pool->used_map, 0, page_cnt, false);
	/* 
		page_cnt개의 페이지를 만들기 위해 HDD의 빈 블록을 찾아야 한다
		bitmap이 0이면 free, 1이면 occupied 블록
		page index를 리턴 받게 되며 해당 page를 의미하는 bitmap은 1로 변경됨
	*/
	// printf("	page_idx: %d\n", page_idx);

	lock_release (&pool->lock); // 작업 마쳤으니 lock 해제
	void *pages;

	if (page_idx != BITMAP_ERROR)
		pages = pool->base + PGSIZE * page_idx; // 주소값 계산. page_idx가 1, 2, 3, 512, 513, ... 이런 식으로 나오니까
	else
		pages = NULL;

	if (pages) { // 페이지 할당이 성공한 경우
		// printf("flags & PAL_ASSERT:%d\nflags & PAL_ZERO:%d\nflags & PAL_USER:%d\n", flags & PAL_ASSERT, flags & PAL_ZERO, flags & PAL_USER);
		if (flags & PAL_ZERO) // flags가 PAL_ZERO로 들어왔으면 메모리를 0으로 초기화
			memset (pages, 0, PGSIZE * page_cnt);
	} else {
		if (flags & PAL_ASSERT)
			PANIC ("palloc_get: out of pages");
	}

	return pages;
}

/* Obtains a single free page and returns its kernel virtual
   address.
   If PAL_USER is set, the page is obtained from the user pool,
   otherwise from the kernel pool.  If PAL_ZERO is set in FLAGS,
   then the page is filled with zeros.  If no pages are
   available, returns a null pointer, unless PAL_ASSERT is set in
   FLAGS, in which case the kernel panics. */
void *
palloc_get_page (enum palloc_flags flags) {
	return palloc_get_multiple (flags, 1);
}

/* Frees the PAGE_CNT pages starting at PAGES. */
void
palloc_free_multiple (void *pages, size_t page_cnt) {
	struct pool *pool;
	size_t page_idx;

	ASSERT (pg_ofs (pages) == 0);
	if (pages == NULL || page_cnt == 0)
		return;

	if (page_from_pool (&kernel_pool, pages))
		pool = &kernel_pool;
	else if (page_from_pool (&user_pool, pages))
		pool = &user_pool;
	else
		NOT_REACHED ();

	page_idx = pg_no (pages) - pg_no (pool->base);

#ifndef NDEBUG
	memset (pages, 0xcc, PGSIZE * page_cnt);
#endif
	ASSERT (bitmap_all (pool->used_map, page_idx, page_cnt));
	bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
}

/* Frees the page at PAGE. */
void
palloc_free_page (void *page) {
	palloc_free_multiple (page, 1);
}

/* Initializes pool P as starting at START and ending at END */
static void
init_pool (struct pool *p, void **bm_base, uint64_t start, uint64_t end) {
  /* We'll put the pool's used_map at its base.
     Calculate the space needed for the bitmap
     and subtract it from the pool's size. */
	uint64_t pgcnt = (end - start) / PGSIZE;
	size_t bm_pages = DIV_ROUND_UP (bitmap_buf_size (pgcnt), PGSIZE) * PGSIZE;

	lock_init(&p->lock);
	p->used_map = bitmap_create_in_buf (pgcnt, *bm_base, bm_pages);
	p->base = (void *) start;

	// Mark all to unusable.
	bitmap_set_all(p->used_map, true);

	*bm_base += bm_pages;
}

/* Returns true if PAGE was allocated from POOL,
   false otherwise. */
static bool
page_from_pool (const struct pool *pool, void *page) {
	size_t page_no = pg_no (page);
	size_t start_page = pg_no (pool->base);
	size_t end_page = start_page + bitmap_size (pool->used_map);
	return page_no >= start_page && page_no < end_page;
}
