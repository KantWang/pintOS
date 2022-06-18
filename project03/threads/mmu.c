#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "intrinsic.h"

static uint64_t *
pgdir_walk(uint64_t *pdp, const uint64_t va, int create)
{
	int idx = PDX(va);
	if (pdp)
	{
		uint64_t *pte = (uint64_t *)pdp[idx];
		if (!((uint64_t)pte & PTE_P))
		{
			if (create)
			{
				uint64_t *new_page = palloc_get_page(PAL_ZERO);
				if (new_page)
					pdp[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
				else
					return NULL;
			}
			else
				return NULL;
		}
		return (uint64_t *)ptov(PTE_ADDR(pdp[idx]) + 8 * PTX(va));
	}
	return NULL;
}

static uint64_t *
pdpe_walk(uint64_t *pdpe, const uint64_t va, int create)
{
	uint64_t *pte = NULL;
	int idx = PDPE(va);
	int allocated = 0;
	if (pdpe)
	{
		uint64_t *pde = (uint64_t *)pdpe[idx];
		if (!((uint64_t)pde & PTE_P))
		{
			if (create)
			{
				uint64_t *new_page = palloc_get_page(PAL_ZERO);
				if (new_page)
				{
					pdpe[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
					allocated = 1;
				}
				else
					return NULL;
			}
			else
				return NULL;
		}
		pte = pgdir_walk(ptov(PTE_ADDR(pdpe[idx])), va, create);
	}
	if (pte == NULL && allocated)
	{
		palloc_free_page((void *)ptov(PTE_ADDR(pdpe[idx])));
		pdpe[idx] = 0;
	}
	return pte;
}

/* Returns the address of the page table entry for virtual
 * address VADDR in page map level 4, pml4.
 * If PML4E does not have a page table for VADDR, behavior depends
 * on CREATE.  If CREATE is true, then a new page table is
 * created and a pointer into it is returned.  Otherwise, a null
 * pointer is returned. */
uint64_t *
pml4e_walk(uint64_t *pml4e, const uint64_t va, int create)
{
	uint64_t *pte = NULL;
	int idx = PML4(va); // PML4E : 39 ~ 47 bit
	int allocated = 0;
	if (pml4e)
	{
		uint64_t *pdpe = (uint64_t *)pml4e[idx];
		if (!((uint64_t)pdpe & PTE_P))
		{
			if (create)
			{
				uint64_t *new_page = palloc_get_page(PAL_ZERO);
				if (new_page)
				{
					pml4e[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
					allocated = 1;
				}
				else
					return NULL;
			}
			else
				return NULL;
		}
		pte = pdpe_walk(ptov(PTE_ADDR(pml4e[idx])), va, create);
	}
	if (pte == NULL && allocated)
	{
		palloc_free_page((void *)ptov(PTE_ADDR(pml4e[idx])));
		pml4e[idx] = 0;
	}
	return pte;
}

/* Creates a new page map level 4 (pml4) has mappings for kernel
 * virtual addresses, but none for user virtual addresses.
 * Returns the new page directory, or a null pointer if memory
 * allocation fails. */

/* 새 페이지 테이블(pml4)을 만들고 반환
 * 커널 가상 페이지는 매핑이 되어있지만 사용자 가상 매핑은 포함되어 있지 않음
 * 메모리를 가져올 수 없는 경우 NULL 포인터를 반환
 */

uint64_t *
pml4_create(void)
{
	uint64_t *pml4 = palloc_get_page(0);
	if (pml4)
		memcpy(pml4, base_pml4, PGSIZE);
	return pml4;
}

static bool
pt_for_each(uint64_t *pt, pte_for_each_func *func, void *aux,
			unsigned pml4_index, unsigned pdp_index, unsigned pdx_index)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pte = &pt[i];
		if (((uint64_t)*pte) & PTE_P)
		{
			void *va = (void *)(((uint64_t)pml4_index << PML4SHIFT) |
								((uint64_t)pdp_index << PDPESHIFT) |
								((uint64_t)pdx_index << PDXSHIFT) |
								((uint64_t)i << PTXSHIFT));
			if (!func(pte, va, aux))
				return false;
		}
	}
	return true;
}

static bool
pgdir_for_each(uint64_t *pdp, pte_for_each_func *func, void *aux,
			   unsigned pml4_index, unsigned pdp_index)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pte = ptov((uint64_t *)pdp[i]);
		if (((uint64_t)pte) & PTE_P)
			if (!pt_for_each((uint64_t *)PTE_ADDR(pte), func, aux,
							 pml4_index, pdp_index, i))
				return false;
	}
	return true;
}

static bool
pdp_for_each(uint64_t *pdp,
			 pte_for_each_func *func, void *aux, unsigned pml4_index)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pde = ptov((uint64_t *)pdp[i]);
		if (((uint64_t)pde) & PTE_P)
			if (!pgdir_for_each((uint64_t *)PTE_ADDR(pde), func,
								aux, pml4_index, i))
				return false;
	}
	return true;
}

/* Apply FUNC to each available pte entries including kernel's. */
bool pml4_for_each(uint64_t *pml4, pte_for_each_func *func, void *aux)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pdpe = ptov((uint64_t *)pml4[i]);
		if (((uint64_t)pdpe) & PTE_P)
			if (!pdp_for_each((uint64_t *)PTE_ADDR(pdpe), func, aux, i))
				return false;
	}
	return true;
}

static void
pt_destroy(uint64_t *pt)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pte = ptov((uint64_t *)pt[i]);
		if (((uint64_t)pte) & PTE_P)
			palloc_free_page((void *)PTE_ADDR(pte));
	}
	palloc_free_page((void *)pt);
}

static void
pgdir_destroy(uint64_t *pdp)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pte = ptov((uint64_t *)pdp[i]);
		if (((uint64_t)pte) & PTE_P)
			pt_destroy(PTE_ADDR(pte));
	}
	palloc_free_page((void *)pdp);
}

static void
pdpe_destroy(uint64_t *pdpe)
{
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
	{
		uint64_t *pde = ptov((uint64_t *)pdpe[i]);
		if (((uint64_t)pde) & PTE_P)
			pgdir_destroy((void *)PTE_ADDR(pde));
	}
	palloc_free_page((void *)pdpe);
}

/* Destroys pml4e, freeing all the pages it references.
 * 페이지 테이블 자체와 pml4가 매핑하는 프레임을 포함하여 pml4가 보유한 모든 리소스를 해제
 * pdpe_destroy, pgdir_destory 및 pt_destroy를 재귀적으로 호출하여 페이지 테이블의 모든 수준에서 모든 리소스를 확보
 */

void pml4_destroy(uint64_t *pml4)
{
	if (pml4 == NULL)
		return;
	ASSERT(pml4 != base_pml4);

	/* if PML4 (vaddr) >= 1, it's kernel space by define. */
	uint64_t *pdpe = ptov((uint64_t *)pml4[0]);
	if (((uint64_t)pdpe) & PTE_P)
		pdpe_destroy((void *)PTE_ADDR(pdpe));
	palloc_free_page((void *)pml4);
}

/* Loads page directory PD into the CPU's page directory base
 * register.
 * pml4를 활성화
 * active page table은 CPU가 메모리 참조를 변환하기 위해 사용하는 테이블
 */
void pml4_activate(uint64_t *pml4)
{
	lcr3(vtop(pml4 ? pml4 : base_pml4));
}

/* Looks up the physical address that corresponds to user virtual
 * address UADDR in pml4.  Returns the kernel virtual address
 * corresponding to that physical address, or a null pointer if
 * UADDR is unmapped. */

/* uaddr에 매핑된 프레임을 pml4에서 조회
 * uaddr이 매핑된 경우 해당 프레임의 커널 가상 주소(kva)를 반환하고
 * 매핑되지 않은 경우 null 포인터를 반환합니다.
 */
void *
pml4_get_page(uint64_t *pml4, const void *uaddr)
{
	ASSERT(is_user_vaddr(uaddr));

	uint64_t *pte = pml4e_walk(pml4, (uint64_t)uaddr, 0);

	if (pte && (*pte & PTE_P))
		return ptov(PTE_ADDR(*pte)) + pg_ofs(uaddr);
	return NULL;
}

/* Adds a mapping in page map level 4 PML4 from user virtual page
 * UPAGE to the physical frame identified by kernel virtual address KPAGE.
 * UPAGE must not already be mapped. KPAGE should probably be a page obtained
 * from the user pool with palloc_get_page().
 * If WRITABLE is true, the new page is read/write;
 * otherwise it is read-only.
 * Returns true if successful, false if memory allocation
 * failed. */

/*
 * user page upage에서 커널 가상 주소 kpage로 식별된 프레임에 대한 pd 매핑을 추가.
 * rw가 참이면 페이지는 읽기/쓰기로 매핑되고, 그렇지 않으면 읽기 전용으로 매핑
 * user page upage가 pml4에 매핑되어 있으면 안됨.
 * kernel page kpage는 palloc_get_page(PAL_USER) (사용자 풀)에서 가져온 커널 가상 주소여야 함.
 * 성공하면 true를 반환하고 실패하면 false를 반환합니다
 * 페이지 테이블에 필요한 추가 메모리를 얻을 수 없는 경우 오류가 발생합니다.
 */
// pa
bool pml4_set_page(uint64_t *pml4, void *upage, void *kpage, bool rw)
{
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(pg_ofs(kpage) == 0);
	ASSERT(is_user_vaddr(upage));
	ASSERT(pml4 != base_pml4);

	uint64_t *pte = pml4e_walk(pml4, (uint64_t)upage, 1);
	// // printf("	%#x	\n", pte);
	if (pte)
		*pte = vtop(kpage) | PTE_P | (rw ? PTE_W : 0) | PTE_U;
	// // printf("	%#x	\n", pte);
	return pte != NULL;
}

/* Marks user virtual page UPAGE "not present" in page
 * directory PD.  Later accesses to the page will fault.  Other
 * bits in the page table entry are preserved.
 * UPAGE need not be mapped. */

/* 페이지를 pml4에 "not present"으로 표시
 * 나중에 페이지에 액세스할 때 오류가 발생
 * 페이지에 대한 페이지 테이블의 다른 비트는 보존되므로 액세스된 비트 및 더티 비트(다음 섹션 참조)를 확인할 수 있음
 * 페이지가 매핑되지 않은 경우 이 함수는 영향을 미치지 않습니다.
 */
void pml4_clear_page(uint64_t *pml4, void *upage)
{
	uint64_t *pte;
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(is_user_vaddr(upage));

	pte = pml4e_walk(pml4, (uint64_t)upage, false);

	if (pte != NULL && (*pte & PTE_P) != 0)
	{
		*pte &= ~PTE_P;
		if (rcr3() == vtop(pml4))
			invlpg((uint64_t)upage);
	}
}

/* Returns true if the PTE for virtual page VPAGE in PML4 is dirty,
 * that is, if the page has been modified since the PTE was
 * installed.
 * Returns false if PML4 contains no PTE for VPAGE. */
/* pml4에 페이지에 대한 pte가 있는 경우 dirty(or accessed) 비트는 지정된 값으로 설정 */
bool pml4_is_dirty(uint64_t *pml4, const void *vpage)
{
	uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
	return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
 * in PML4. */
/* pml4에 페이지에 대한 pte가 있는 경우,
 * dirty bit는 지정된 값(bool dirty)으로 설정 */
void pml4_set_dirty(uint64_t *pml4, const void *vpage, bool dirty)
{
	uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
	if (pte)
	{
		if (dirty)
			*pte |= PTE_D; // dirty bit이 참이라면 1로 설정
		else
			*pte &= ~(uint32_t)PTE_D; // dirty bit이 false라면 0으로 설정

		if (rcr3() == vtop(pml4))
			invlpg((uint64_t)vpage);
	}
}

/* Returns true if the PTE for virtual page VPAGE in PML4 has been
 * accessed recently, that is, between the time the PTE was
 * installed and the last time it was cleared.  Returns false if
 * PML4 contains no PTE for VPAGE. */
bool pml4_is_accessed(uint64_t *pml4, const void *vpage)
{
	uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
	return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void pml4_set_accessed(uint64_t *pml4, const void *vpage, bool accessed)
{
	uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
	if (pte)
	{
		if (accessed)
			*pte |= PTE_A;
		else
			*pte &= ~(uint32_t)PTE_A;

		if (rcr3() == vtop(pml4))
			invlpg((uint64_t)vpage);
	}
}
