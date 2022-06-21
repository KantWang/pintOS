/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "include/threads/mmu.h"
#include "include/threads/vaddr.h"
#include "include/userprog/process.h"

struct list frame_table;
// struct list_elem *clock_pointer;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
	
	/* -------------------------- */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or `vm_alloc_page`.
 * 커널이 새 페이지 요청을 수신할 때 호출
 */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{	
	//printf("	@@@ vm_alloc_page_with_initializer @@@\n");
	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;
	/* Check whether the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		//// //printf("	### vm_alloc_page_with_initializer - spt_find_page == NULL ###\n");
		/* TODO: Create the page, fetch the initialier according to the VM type,
		// 전달받은 aux에 따라 INIT을 호출?
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		page = (struct page *)malloc(sizeof(struct page));
		bool (*initializer)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initializer = &anon_initializer;
			break;

		case VM_FILE:
			initializer = &file_backed_initializer;
			break;
		default:
			goto err;
		}

		//printf("	@@@ uninit_new - upage - before round_down: %p @@@\n", upage);
		upage = pg_round_down(upage);
		//printf("	@@@ uninit_new - upage - after round_down: %p @@@\n", upage);
		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page) ? true : false;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// Find struct page that corresponds to va from the given supplemental page table. If fail, return NULL.

struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function. */

	struct page tmp;
	struct hash_elem *h = NULL;
	tmp.va = pg_round_down(va);

	h = hash_find(&spt->hash, &tmp.h_elem);
	if (h == NULL)
	{
		return NULL;
	}
	// //// //printf("	### after hash_find ###\n");
	struct page *p = hash_entry(h, struct page, h_elem);
	// //// //printf("	### after hash_entry : %p ###\n",p);
	
	return p;
}
/* Insert PAGE into spt with validation. */
// Insert 'struct page' into the given supplemental page table. This function should checks that the virtual address does not exist in the given supplemental page table.
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	// printf("	$$$ spt_insert_page - page: %p $$$\n", page);
	/* TODO: Fill this function. */
	// page->va = pg_round_down(page->va);
	if (!hash_insert(&spt->hash, &page->h_elem)) // hash_insert는 삽입 성공 시 0을 반환 (헷갈리면 안됨)
		return true;

	return false;
}

/* Delete PAGE from spt */
bool spt_delete_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	hash_delete(&spt->hash, &page->h_elem);
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{	
	struct frame *victim = NULL;
	struct list_elem *clock_pointer = list_begin(&frame_table);
	uint64_t *pml4 = &thread_current()->pml4;
	
	while (1) {
		// printf("	### vm_get_victim ###\n");
		victim = list_entry(clock_pointer, struct frame, f_elem);
		// printf("	### victim: %p ###\n", victim);

		if (pml4_is_accessed(pml4, victim->page->va)) {
			// printf("	### vm_get_victim - if ###\n");
			pml4_set_accessed(pml4, victim->page->va, 0);
			clock_pointer = list_next(clock_pointer);
			if (clock_pointer == NULL)
				clock_pointer = list_begin(&frame_table);
		}
		else {
			// printf("	### vm_get_victim - else ###\n");
			return victim;
		}
	}

	/* TODO: The policy for eviction is up to you. */
	// struct list_elem *tmp_elem = list_begin(&frame_table);
	// uint64_t *pml4 = &thread_current()->pml4;
	// for (tmp_elem; tmp_elem != list_end(&frame_table); tmp_elem = list_next(tmp_elem))
	// {
	// 	victim = list_entry(tmp_elem, struct frame, f_elem);
	// 	if (pml4_is_accessed(pml4, victim->page->va))
	// 	{
	// 		pml4_set_accessed(pml4, victim->page->va, 0);
	// 	}
	// 	else
	// 	{
	// 		// clock_pointer = tmp_elem;
	// 		return victim;
	// 	}
	// }

	// for (tmp_elem = list_begin(&frame_table); tmp_elem != list_end(&frame_table); tmp_elem = list_next(tmp_elem))
	// {
	// 	victim = list_entry(tmp_elem, struct frame, f_elem);
	// 	if (pml4_is_accessed(pml4, victim->page->va))
	// 	{
	// 		pml4_set_accessed(pml4, victim->page->va, 0);
	// 	}
	// 	else
	// 	{
	// 		return victim;
	// 	}
	// }
	// return NULL;

	// struct frame *victim = NULL;
    // if (list_entry(list_begin(&frame_table), struct frame, f_elem))
    // {
	// 	victim = list_entry(list_pop_back(&frame_table), struct frame, f_elem);
    //     return victim;
    // }
    // return NULL;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	/* ******************************************************* */
	//printf("	### vm_evict_frame ###\n");
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */
	// if(!swap_out(victim->page))
	// 	return NULL;
	/* ------------------------------------------------------- */
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/

/* palloc_get_page를 호출하여 사용자 풀에서 새 실제 페이지를 가져옵니다.
 * Gets a new physical page from the user pool by calling palloc_get_page. When successfully got a page from the user pool, also allocates a frame, initialize its members, and returns it. After you implement vm_get_frame, you have to allocate all user space pages (PALLOC_USER) through this function. You don't need to handle swap out for now in case of page allocation failure. Just mark those case with PANIC ("todo") for now.

 * 사용자 풀에서 페이지를 성공적으로 가져오면 프레임도 할당하고 구성원을 초기화한 다음 반환합니다.
 * vm_get_frame을 구현한 후에는 이 기능을 통해 모든 사용자 공간 페이지(PALLOC_USER)를 할당해야 합니다. 페이지 할당에 실패하는 경우 지금은 스왑 아웃을 처리할 필요가 없습니다.
 * 일단 이 경우 PANIC("TO DO")으로 표시하십시오. */
static struct frame *
vm_get_frame(void)
{
	//printf("	### vm_get_frame ###\n");
	struct frame *frame = NULL;
	void *victim = palloc_get_page(PAL_USER);
	// // printf("	frame: %p\n", frame);

	/* TODO: Fill this function. */
	if (victim == NULL)
	{
		// printf("\n	### swap-out start ###\n");
		frame = vm_evict_frame();
		if (!swap_out(frame->page))
			return NULL;
		
		free(frame);
		victim = palloc_get_page(PAL_USER); // 다시 시도
		if (victim == NULL)
			return NULL;
	}

	frame = (struct frame *)malloc(sizeof(struct frame));
	frame->kva = victim;
	frame->page = NULL;
	list_push_back(&frame_table, &frame->f_elem);

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Claim the page that allocate on VA. */
/* va를 할당하도록 페이지를 클레임합니다.
 * 먼저 페이지를 받은 후 vm_do_claim_page를 호출해야 합니다.*/
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	struct supplemental_page_table *spt = &thread_current()->spt;
	/* TODO: Fill this function */
	page = spt_find_page(spt, va);
	return page != NULL ? vm_do_claim_page(page) : false;
}

/* Claim the PAGE and set up the mmu. */
/* vm_get_frame을 호출하여 프레임을 얻습니다(템플릿에서 이미 수행됨).
 * 가상 주소에서 페이지 테이블의 실제 주소로 매핑을 추가
 * 반환 값은 작업의 성공 여부를 나타내야 합니다 (True or False).
 */
static bool
vm_do_claim_page(struct page *page)
{
	// //// //printf("	### do_clame_page ###\n");
	struct frame *frame = vm_get_frame();
	// // //printf("	### vm_do_claim_page - frame: %p, page va: %p ###\n", frame, page->va);
	/*
		0x8004280938      0x8004280938
		0x800423e198      0x800423e058
		0x0000042740      0x0000042880
	*/
	struct thread *curr = thread_current();
	/* Set links */
	frame->page = page;
	page->frame = frame;

	if (pml4_get_page(curr->pml4, page->va) == NULL && pml4_set_page(curr->pml4, page->va, frame->kva, page->writable)){
		// //printf("	### pml4_get & set_page pass ###\n");
		//// //printf("	### swap_in 위 ###\n");
		return swap_in(page, frame->kva);
	}

	// //printf("	### vm_do_claim_page - false ###\n");
	//// //printf("	### vm_do_claim_page - return false ###\n");
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	return false;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	// // printf("	sg\n");
	// addr = pg_round_down(addr);
	if (USER_STACK - 0x100000 <= addr)
	{
		// // printf("	inin\n");
		vm_alloc_page(VM_ANON | VM_MARKER_0, addr, 1);
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

// addr 주소를 포함하도록 스택을 확장
// 최대 1MB까지 스택 확장 가능
// static void expand_stack(void *addr UNUSED) { // 이미 pg_round_down 처리 완료
// 	// bool success = false;

// 	// vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
// 	// success = vm_claim_page(addr);

// 	// return success;
// 	addr = pg_round_down(addr);
// 	if (USER_STACK - 0x100000 + PGSIZE <= addr)
// 	{
// 		vm_alloc_page(VM_ANON | VM_MARKER_0, addr, 1);
// 	}
// }

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	void *rsp = (void *)(user ? f->rsp : thread_current()->rsp);
	// // printf("	rsp: %p\n", rsp);
	// // printf("	addr: %p\n", addr);

	if (!not_present)
	{
		//// //printf("	### vm_try_handle_fault - !not_present ###\n");
		exit(-1);
	}

	if (not_present)
	{
		// USER_STACK - 1mb <= addr <= USER_STACK
		// case 1 : rsp - addr == 0x8
		// case 2 :  (USER_STACK - 0x100000 <= addr)  (USER_STACK - 0x100000 <= addr)
		if ((addr < USER_STACK && addr >= rsp) || rsp - addr == 0x8)
		{
			vm_stack_growth(addr);
		}
	}

	/* --------------------------------- */
	// printf("	!!!!addr: %p\n", addr);
	page = spt_find_page(spt, addr);
	//// //printf("	### vm_try_handle_fault - page: %p ###\n", page);
	// printf("	page: %p\n", page);
	return page != NULL ? vm_do_claim_page(page) : false;

	// /* stack growth */
	// if ((addr < USER_STACK && addr >= rsp) || rsp - addr == 0x8) {
	// 	// // printf("	ㅇㅕㄱㅣㄹㅗ?\n");
	// 	addr = pg_round_down(addr);
	// 	if (addr >= USER_STACK_END) {
	// 		if (!expand_stack(addr)){
	// 			return false;
	// 		}
	// 		return true;
	// 	}
	// 	else
	// 		return false;
	// }
	// else { // not stack
	// 	// // printf("	ㅇㅏㄴㅣㅁ ㅇㅕㄱㅣ?\n");
	// 	page = spt_find_page(spt, addr);
	// 	return page ? vm_do_claim_page(page) : false;
	// }
}
/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	// todo 2: This is used when a child needs to inherit the execution context of its parent (i.e. fork()).
	// todo 2: Iterate through each page in the src's supplemental page table and make a exact copy of the entry in the dst's supplemental page table.
	// todo 2: You will need to allocate uninit page and claim them immediately.
	struct hash_iterator *i = malloc(sizeof(struct hash_iterator));
	hash_first(i, &src->hash);

	// for (; i != NULL; i = hash_next(i))
	while(hash_next(i))
	{	
		struct page *p_page = hash_entry(i->elem, struct page, h_elem); // 부모 page
		struct page *c_page; // 자식 page
		enum vm_type parent_type = p_page->operations->type;

		if (p_page->operations->type == VM_UNINIT) { 	
			struct segment *parent_aux = malloc(sizeof(struct segment));
			if (parent_aux)
				memcpy(parent_aux, p_page->uninit.aux, sizeof(struct segment));
			if (!vm_alloc_page_with_initializer(page_get_type(p_page), p_page->va, 
															p_page->writable, p_page->uninit.init, parent_aux))
				return false;
		}
		else {
			if (p_page->uninit.type & VM_MARKER_0) { // stack인 경우
				if(!setup_stack(&thread_current()->tf))
					return false;
			}
			else { // parent_p->operations->type == VM_ANON 또는 VM_FILE인 경우
				if(!vm_alloc_page_with_initializer(page_get_type(p_page), p_page->va, 
											p_page->writable, NULL, NULL)) // 뒤에 두 개 정보가 필요 없다
					return false;
				if(!vm_claim_page(p_page->va)) // 이곳을 vm_do_claim_page로 하면 돼 안돼?
					return false;
			}
			c_page = spt_find_page(dst, p_page->va); // 왜 필요한지 이해하자
			memcpy(c_page->frame->kva, p_page->frame->kva, PGSIZE);
		}
	}
	return true; // 이놈 빼먹으면 돼 안돼?
}

void page_destructor(struct hash_elem *h, void *aux UNUSED)
{
	/* Get hash element (hash_entry() 사용) */
	struct page *p = hash_entry(h, struct page, h_elem);
	vm_dealloc_page(p);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	// struct hash_iterator *i = malloc(sizeof(struct hash_iterator));
	hash_destroy(&spt->hash, page_destructor);
	// size_t i;
	// for (i = 0; i < spt->hash.bucket_cnt; i++)
	// {
	// 	struct list *bucket = &spt->hash.buckets[i];

	// 	while (!list_empty(bucket))
	// 	{
	// 		struct list_elem *list_elem = list_pop_front(bucket);
	// 		struct hash_elem *hash_elem = list_elem_to_hash_elem(list_elem);
	// 		page_destructor(hash_elem, spt->hash.aux);
	// 	}
	// 	list_init(bucket);
	// }

	// *(&spt->hash.elem_cnt) = 0;

	// hash_destroy(&spt->hash, page_destructor);
}


/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, h_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, h_elem);
	const struct page *b = hash_entry(b_, struct page, h_elem);

	return a->va < b->va;
}