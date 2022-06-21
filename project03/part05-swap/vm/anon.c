/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
/* project03 - swap in/out */
#include "include/threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
struct bitmap *swap_table;
int bitcnt;
const size_t sector_num_per_page = PGSIZE / DISK_SECTOR_SIZE; // 페이지당 8개의 SECTOR

/* 
스왑 디스크에서 사용 가능한 영역과 사용된 영역을 관리하기 위한 자료구조로 bitmap 사용
스왑 영역은 PGSIZE 단위로 관리 => 기본적으로 스왑 영역은 디스크이니 섹터로 관리하는데
이를 페이지 단위로 관리하려면 섹터 단위를 페이지 단위로 바꿔줄 필요가 있음.
이 단위가 SECTORS_PER_PAGE! (8섹터 당 1페이지 관리)
*/

static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
	// // //printf("	### vm_anon_init ###\n");
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
    swap_table = bitmap_create(disk_size(swap_disk) / 8);
	
	// int swap_size = disk_size(swap_disk) / sector_num_per_page; // swap_disk에 들어갈 수 있는 page의 개수
	// // ### disk_size: 60480 ###
	// // ### swap_size: 7560 ###
    // swap_table = bitmap_create(swap_size); // page 개수 만큼 bitmap create. 모든 bit가 0으로 설정됨
	/*
		b->bits = malloc(byte_cnt(bit_cnt));
		                 byte_cnt(bit_cnt): 952
	*/
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &anon_ops;
	// struct uninit_page *uninit = &page->uninit;
	// memset(uninit, 0, sizeof(struct uninit_page));
	struct anon_page *anon_page = &page->anon;
	anon_page->swap_slot = 0;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva)
{
	// //printf("	### anon_swap_in ###\n");
	struct anon_page *anon = &page->anon;
	int page_no = anon->swap_slot;
	// printf("	$$$ page_no: %d $$$\n", page_no);
	// if (!bitmap_test(swap_table, page_no)) // 952byte 중 page_no 번째 1byte의 8개 bit가 모두 0인지 확인
    //     return false;
	
	for (int i = 0; i < sector_num_per_page; i++) {
		
		disk_read(swap_disk, page_no * sector_num_per_page + i, kva + DISK_SECTOR_SIZE * i);
		//        disk*    , 읽기 시작할 위치                  , 데이터를 저장할 곳의 주소 
	}
	
	bitmap_set(swap_table, page_no, false);
	// //printf("	### anon_swap_in - bitmap_set ###\n");
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page)
{
	// //printf("	### anon_swap_out ###\n");
	struct anon_page *anon_page = &page->anon;

	// 사용 가능한 bit 찾은 후 swap disk에 write & bitmap은 역전
	int page_no = bitmap_scan_and_flip(swap_table, 0, 1, false);
	if (page_no == BITMAP_ERROR)
		return false;
	
	// 1페이지(8개 섹터)에 write
	for (int i = 0; i < sector_num_per_page; i++) {
		disk_write(swap_disk, page_no * sector_num_per_page + i, page->va + i * DISK_SECTOR_SIZE); 
	}

	anon_page->swap_slot = page_no;
	pml4_clear_page(thread_current()->pml4, page->va); // pte의 present bit만 0으로 바꿔주면 된다?
	palloc_free_page(page->frame->kva);
	
	// frame, spt table에서 제거하기 --> spt 테이블에서 왜 제거해
	list_remove(&page->frame->f_elem);	

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page)
{
}
