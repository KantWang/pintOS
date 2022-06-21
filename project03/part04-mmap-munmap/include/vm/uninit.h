#ifndef VM_UNINIT_H
#define VM_UNINIT_H
#include "vm/vm.h"

struct page;
enum vm_type;

typedef bool vm_initializer(struct page *, void *aux);

/* Uninitlialized page. The type for implementing the
 * "Lazy loading". */
struct uninit_page
{
	/* Initiate the contets of the page */
	vm_initializer *init; // lazy_load_segment
	enum vm_type type;	  // original page type
	void *aux;			  // struct segment로 쓰이는 변수
	/* Initiate the struct page and maps the pa to the va */
	bool (*page_initializer)(struct page *, enum vm_type, void *kva); // (vm_do_claim_page -> swap-in -> uninit_initialize) 에서 실행
};

void uninit_new(struct page *page, void *va, vm_initializer *init,
				enum vm_type type, void *aux,
				bool (*initializer)(struct page *, enum vm_type, void *kva));
#endif
