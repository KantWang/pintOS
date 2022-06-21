/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "include/threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);
static bool lazy_load_file (struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	// //printf("	### file_backed_initializer ### 진입 \n");
	/* Set up the handler */
	page->operations = &file_ops;

	/* project3 */
	struct uninit_page *uninit = &page->uninit;
	memset(uninit, 0, sizeof(struct uninit_page));

	/* -------------------------------------- */
	struct file_page *file_page = &page->file;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{
	struct segment *aux UNUSED = page->file.file_aux;
	struct thread *t = thread_current();
	
	if (pml4_is_dirty(t->pml4, page->va)) {
		file_write_at(aux->file, page->frame->kva, aux->written_bytes, aux->ofs);
		pml4_set_dirty(t->pml4, page->va, 0);
	}
	free(aux);
}

/* project03 - mmap, munmap */
static bool
lazy_load_file (struct page *page, void *aux) {
	//printf("	### lazy_load_file ###\n");
	struct segment *aux_data = aux;
	struct file *f = aux_data->file;
	off_t ofs = aux_data->ofs;
	uint32_t page_read_bytes = aux_data->read_bytes;
	uint32_t page_zero_bytes = aux_data->zero_bytes;
	
	//struct file_page 안 file_aux에 정보 넣어주기
	page->file.file_aux = (struct segment*)malloc(sizeof(struct segment));
	memcpy(page->file.file_aux, aux_data, sizeof(struct segment));

	// page->file.page_count = aux_data->page_count;
	// page->file.page_ofs = ofs;
	// page->file.file_addr = f;

	file_seek(f, ofs);
	//printf("	### lazy_load_file - file_seek ###\n");
	size_t written_bytes = file_read(f, page->frame->kva, page_read_bytes);
	if (written_bytes == NULL)
	{
		return false;
	}

	page->file.file_aux->written_bytes = written_bytes;
	//printf("	### lazy_load_file - file_read ###\n");
	
	// if (page->file.written_bytes = file_read(f, page->frame->kva, page_read_bytes) != (int)page_read_bytes) {
	// 	return false;
	// }
	
	memset(page->frame->kva + page_read_bytes, 0, page_zero_bytes);
	//printf("	### lazy_load_file - memset ###\n");
	free(aux_data);

	return true;
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	//printf("	@@@ do_mmap @@@, addr: %p\n", addr);
	if((long)length < offset) 
		return NULL;

	struct file *ofile = file_reopen(file);
	void *origin_addr = addr;
	//printf("	@@@ spt_find_page @@@\n");
	if (spt_find_page(&thread_current()->spt, addr) != NULL)
		return NULL;
	
	int page_count = (length % PGSIZE ? (int)(length/PGSIZE) + 1 : (int)(length/PGSIZE));

	long zero_bytes = 0;
	while (length > 0 || zero_bytes > 0) {
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		//printf("	@@@ do_mmap - while - length: %d, zero_bytes: %d ###\n", length, zero_bytes);

		struct segment *segment = malloc(sizeof(struct segment));
		segment->ofs = offset;
		segment->read_bytes = page_read_bytes;
		segment->zero_bytes = page_zero_bytes;
		segment->file = ofile;

		segment->page_count = page_count;
		//printf("	### do_mmap - page_count: %d ###\n", page_count);
		//printf("	### segment->page_count: %d ###\n", segment->page_count);
		void *aux = segment;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_file, aux)){
			//printf("	### do_mmap - vm_alloc_page_with_initializer ###\n");
			return NULL;
		}

		length -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		// //printf("	### *addr: %d ###\n", *(int*)addr);
		offset += page_read_bytes;
	}

	return origin_addr;
}

/* Do the munmap */
void do_munmap(void *addr)
{
	//printf("	### do_munmap ###\n");
	struct thread *t = thread_current();
	struct page *page = spt_find_page(&t->spt, addr);
	//printf("	### page: %p ###\n", page);
	if(!page) 
		return;
	//printf("	### spt_find_page ###\n");

	int unmap_count = 0;
	// struct file_page *fp = &page->file;
	struct segment *aux = page->file.file_aux;

	while (unmap_count < aux->page_count) {
		//printf("	### unmap_count: %d, fp->page_count: %d ###\n", unmap_count, fp->page_count);
		if (pml4_is_dirty(t->pml4, page->va)) {
			file_write_at(aux->file, page->frame->kva, aux->written_bytes, aux->ofs);
			pml4_set_dirty(t->pml4, page->va, 0);
		}

		spt_delete_page(&t->spt, page);
		unmap_count += 1;
		// addr += PGSIZE;
		page = spt_find_page(&t->spt, addr + PGSIZE);
			if(!page) return;
		
		aux = page->file.file_aux;
	}
}
