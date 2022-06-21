#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"
#include "lib/kernel/hash.h"

enum vm_type
{
	/* page not initialized */
	VM_UNINIT = 0,
	/* page not related to the file, aka anonymous page */
	VM_ANON = 1,
	/* page that realated to the file */
	VM_FILE = 2,
	/* page that hold the page cache, for project 4 */
	VM_PAGE_CACHE = 3,

	/* Bit flags to store state */

	/* Auxillary bit flag marker for store information. You can add more
	 * markers, until the value is fit in the int. */
	VM_MARKER_0 = (1 << 3), // stack
	VM_MARKER_1 = (1 << 4), // segment
	/* DO NOT EXCEED THIS VALUE. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type)&7)

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page
{
	const struct page_operations *operations;
	void *va;			 /* virtual address */
	struct frame *frame; /* Back reference for frame */

	/* Your implementation */
	struct hash_elem h_elem; /* Hash table element. */
	bool writable;			 /* page 읽기 권한 */

	/* Per-type data are binded into the union.
	 * Each function automatically detects the current union */
	union
	{
		struct uninit_page uninit; // 페이지 생성 시 초기값
		struct anon_page anon;	   // swap-in
		struct file_page file;	   // swap-in
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* The representation of "frame" */
struct frame
{
	void *kva; // kernel virtual address
	struct page *page;

	struct list_elem f_elem;
};

struct segment
{
	off_t ofs;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	struct file *file;
	int page_count;
	size_t written_bytes;
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations
{
	bool (*swap_in)(struct page *, void *);
	bool (*swap_out)(struct page *);
	void (*destroy)(struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page) (page)->operations->swap_out(page)
#define destroy(page)                \
	if ((page)->operations->destroy) \
	(page)->operations->destroy(page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table
{
	struct hash hash;
};

struct mmap_page_table
{
	struct hash hash;
};

#include "threads/thread.h"
void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
								  struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);

struct page *spt_find_page(struct supplemental_page_table *spt,
						   void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

bool spt_delete_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED);

bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
						 bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
									bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);

bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED);
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED);

static void vm_stack_growth(void *addr UNUSED);
void page_destructor(struct hash_elem *h, void *aux UNUSED);
// addr 주소를 포함하도록 스택을 확장
// 최대 1MB까지 스택 확장 가능
static void expand_stack(void *addr UNUSED);

/* project03 - mmap, munmap */
// 이게 file_page다 이 바보야
struct mmap_file {
	int mapid;
	void *uaddr;
	struct file *file;
	struct list_elem elem;
	struct mmap_page_table mpt;
};

#endif /* VM_VM_H */
