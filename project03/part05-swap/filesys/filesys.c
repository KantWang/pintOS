#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
	filesys_disk = disk_get(0, 1);
	if (filesys_disk == NULL)
		PANIC("hd0:1 (hdb) not present, file system initialization failed");

	inode_init();

#ifdef EFILESYS
	fat_init();

	if (format)
		do_format();

	fat_open();
#else
	/* Original FS */
	free_map_init();

	if (format)
		do_format();

	free_map_open();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void)
{
	/* Original FS */
#ifdef EFILESYS
	fat_close();
#else
	free_map_close();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size)
{
	disk_sector_t inode_sector = 0;
	struct dir *dir = dir_open_root();
	bool success = (dir != NULL && free_map_allocate(1, &inode_sector) && inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release(inode_sector, 1);
	dir_close(dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
	struct dir *dir = dir_open_root(); // 루트 디렉토리 오픈
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup(dir, name, &inode); // 해당 dir에 해당되는 name에 해당되는 inode에 저장
	dir_close(dir);					   // 디렉토리는 쓰고 닫아야 함

	return file_open(inode);		   // 해당 inode로 연 파일 객체를 리턴

	/* inode란? 리눅스 시스템에서, 파일 시스템을 처리할 때, 리눅스 전용 특수한 인덱스를 아이노드라고 한다. 
	 * 아이노드는 index-node의 줄임말이다. 이름에서 유추할 수 있듯이 무언가를 빠르게 찾기위한 노드이며, 
	 * 그 무언가는 리눅스 시스템에서 파일을 의미한다. 즉, 아이노드는 리눅스의 모든 파일에 일종의 번호를 부여한다. 
	 * 아이노드는 파일에 대한 정보(메타데이터)를 포함하고 있고, 인덱스 값도 가진 노드(데이터)이다. 
	 */
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
	struct dir *dir = dir_open_root();
	bool success = dir != NULL && dir_remove(dir, name);
	dir_close(dir);

	return success;
}

/* Formats the file system. */
static void
do_format(void)
{
	printf("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create();
	fat_close();
#else
	free_map_create();
	if (!dir_create(ROOT_DIR_SECTOR, 16))
		PANIC("root directory creation failed");
	free_map_close();
#endif

	printf("done.\n");
}
