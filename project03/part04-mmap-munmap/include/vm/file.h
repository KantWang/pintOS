#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

// struct file_page {
// 	int mapid;
// 	struct file* file;
// 	struct list_elem elem;
// 	struct list vme_list;
// };

struct file_page {
	struct segment *file_aux;
	// int page_count;
	// off_t page_ofs;
	// struct file *file_addr;
	// size_t written_bytes;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
