// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <assert.h>
#include <block_meta.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define MMAP_THRESHOLD (128 * 1024)
#define METADATA_SIZE sizeof(struct block_meta)
#define MULT_KB 1024

int inc_sz_sm[] = {10, 25, 40, 80, 160, 350, 421, 633, 1000, 2024, 4000};
int dec_sz_sm[] = {4023, 2173, 1077, 653, 438, 342, 160, 82, 44, 25, 10};
int alt_sz_sm[] = {1934, 3654, 23, 432, 824, 12, 2631, 827, 375, 30, 26};
int inc_sz_md[] = {5 * MULT_KB, 46 * MULT_KB + 145, 100 * MULT_KB + 732,
				200 * MULT_KB, 523 * MULT_KB + 6342, 1000 * MULT_KB + 3754};
int inc_sz_lg[] = {200 * MULT_KB, 525 * MULT_KB + 6342, 1024 * MULT_KB,
				5256 * MULT_KB + 12462};

struct block_meta first_block;
unsigned int threshold = MMAP_THRESHOLD;
int list_size;

void split_block(struct block_meta *block, int size)
{
	if (block->size < size + METADATA_SIZE + 8) {
		block->status = 1;
		return;
	}
	struct block_meta *new = (void *)block + METADATA_SIZE + size;

	new->status = 0;
	new->size = block->size - size - METADATA_SIZE;
	new->next = block->next;
	new->prev = block;
	block->status = 1;
	block->size = size;
	block->next = new;
}

struct block_meta *alloc_block(int size)
{
	if (size + METADATA_SIZE <= threshold) {
		if (list_size == 0) {
			struct block_meta *block = sbrk(131072);

			block->size = 131072 - METADATA_SIZE;
			block->status = 0;
			block->next = NULL;
			block->prev = NULL;
			split_block(block, size);
			list_size += size;
			return block;
		}
			void *request = sbrk(size + METADATA_SIZE);
			struct block_meta *block = request;

			block->size = size;
			block->status = 1;
			block->next = NULL;
			block->prev = NULL;
			list_size += size;
			return block;
	} else {
		void *request = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		struct block_meta *block = request;

		block->size = size;
		block->status = 2;
		block->next = NULL;
		block->prev = NULL;
		return block;
	}
}

struct block_meta *add_block_to_list(int size)
{
	struct block_meta *current = &first_block;

	while (current->next != NULL)
		current = current->next;
	struct block_meta *block = alloc_block(size);

	current->next = block;
	block->prev = current;
	return block;
}

void coalesce(struct block_meta *block)
{
	struct block_meta *next_block = block->next;

	block->size += next_block->size + METADATA_SIZE;
	block->next = next_block->next;
	next_block->prev = block;
}

void coalesce_free_blocks(struct block_meta *start)
{
	struct block_meta *current = start->next;
	struct block_meta *prev = start;

	while (current != NULL) {
		if (current->status == 0 && prev->status == 0) {
			coalesce(prev);
			current = prev;
		}
		prev = current;
		current = current->next;
	}
}

struct block_meta *find_free_block(int size)
{
	struct block_meta *current = &first_block;
	struct block_meta *best_fit = NULL;

	while (current->next != NULL) {
		current = current->next;
		if (current->status == 0 && (int)current->size >= size) {
			if (best_fit == NULL || current->size < best_fit->size) {
				best_fit = current;
				break;
			}
		}
	}
	if (best_fit != NULL && (int)best_fit->size >= size) {
		split_block(best_fit, size);
	} else if (best_fit == NULL && current->status == 0) {
		struct block_meta *next =
		    add_block_to_list(size - current->size - METADATA_SIZE);
		next->status = 0;
		coalesce_free_blocks(current);
		current->size = size;
		current->status = 1;
		best_fit = current;
	}
	return best_fit;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size = (size + 7) & ~7;
	if (list_size == 0) {
		first_block.next = NULL;
		first_block.size = 0;
		first_block.status = 1;
	}
	struct block_meta *block = NULL;

	if (size + METADATA_SIZE <= threshold) {
		coalesce_free_blocks(&first_block);
		block = find_free_block(size);
	}
	if (block == NULL)
		block = add_block_to_list(size);
	return block + 1;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *block = NULL;
	struct block_meta *current = &first_block;

	while (current != NULL) {
		if (current + 1 == ptr) {
			block = current;
			break;
		}
		current = current->next;
	}
	if (block == NULL)
		return;
	if (block->status == 2) {
		struct block_meta *current = &first_block;

		while (current->next != NULL) {
			if (current->next == block)
				break;
			current = current->next;
		}
		current->next = block->next;
		munmap(block, block->size + METADATA_SIZE);
	} else {
		block->status = 0;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size == 0 || nmemb == 0)
		return NULL;
	int total_size = size * nmemb;

	total_size = (total_size + 7) & ~7;
	int page_size = getpagesize();

	threshold = page_size;
	if (list_size == 0) {
		first_block.next = NULL;
		first_block.prev = NULL;
		first_block.size = 0;
		first_block.status = 1;
	}
	struct block_meta *block = NULL;

	if ((int)(total_size + METADATA_SIZE) <= page_size) {
		coalesce_free_blocks(&first_block);
		block = find_free_block(total_size);
	}
	if (block == NULL)
		block = add_block_to_list(total_size);
	void *mem = (block + 1);

	memset(mem, 0, total_size);
	threshold = MMAP_THRESHOLD;
	return mem;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	size = (size + 7) & ~7;
	struct block_meta *block = NULL;
	struct block_meta *current = &first_block;
	struct block_meta *new_block;

	while (current != NULL) {
		if (current + 1 == ptr) {
			block = current;
			break;
		}
		current = current->next;
	}
	if (block->status == 2 || size + METADATA_SIZE > MMAP_THRESHOLD) {
		void *mem = os_malloc(size);

		if (size < block->size)
			memcpy(mem, ptr, size);
		else
			memcpy(mem, ptr, block->size);
		os_free(ptr);
		return mem;
	} else if (block->status == 1) {
		if (size <= block->size) {
			split_block(block, size);
			new_block = block;
		}
		while (block->size < size && block->next != NULL &&
		       block->next->status == 0) {
			coalesce(block);
		}
		if (block->size >= size) {
			split_block(block, size);
			new_block = block;
		} else if (block->next == NULL) {
			add_block_to_list(size - block->size - METADATA_SIZE);
			coalesce(block);
			block->status = 1;
			new_block = block;
		} else {
			new_block = NULL;
		}
		if (new_block == NULL) {
			void *mem = os_malloc(size);

			memcpy(mem, ptr, block->size);
			os_free(ptr);
			return mem;
		}
	} else {
		return NULL;
	}
	return new_block + 1;
}
