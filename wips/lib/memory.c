#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "memory.h"
#include "eventInfo.h"

memstat mstat [MODULE_MAX]; 


memstat* alloc_inc (int type)
{
  mstat[type].alloc_times++;
  return &mstat[type];
}

memstat* alloc_dec (int type)
{
  mstat[type].alloc_times--;
  return &mstat[type];
}



/* Callback functions */
static int mm_compare(const void *data1, const void *data2)
{
	memory_allocation *d1 = (memory_allocation *)data1;
	memory_allocation *d2 = (memory_allocation *)data2;
	
	if(d1 || d2)
	{
		if(d2->pt > d1->pt)
			return 1;
		else if (d2->pt < d1->pt)
			return -1;
	}
	
	return 0;
}
static void mm_free_struct(void *data)
{
	if(data)
	{
		memory_allocation *toFree = (memory_allocation *)data;
		memstat *toDec = (memstat *)toFree->loop_back;
		toDec->alloc_size -= toFree->size;
		if(toFree->file)
			free(toFree->file);
		
		free(toFree);
	}
}

static int mm_nbofallocs=0;
static int mm_sizeofallocs=0;


/* the real functions */

void *mm_malloc(int type, size_t sz, char *file, int line)
{
	void *data = malloc(sz);
	if(data)
	{
		memory_allocation *allocation = (memory_allocation *)malloc(sizeof(memory_allocation));
		if(allocation)
		{
			/* allocate filename (it's on the stack right now) */
			char *filename = NULL;
			int size = strlen(file);
			filename = (char *)calloc(size+1, sizeof(char));
			mstat[type].alloc_times++;
			mstat[type].alloc_size+=sz;
			memcpy(filename, file, size + 1);
			/* fill the allocation data */
			allocation->pt = data;
			allocation->file = filename;
			allocation->line = line;
			allocation->size = sz;
			allocation->loop_back = &mstat[type];
			/* insert in the tree */
			bstree_add(&mstat[type].mm_root, (void *)allocation, mm_compare);
			//printf("[MM] Alloc'ed %d bytes at %s:%d\n",allocation->size,allocation->file,allocation->line);
		}
		else {
			//printf("[MM] Allocation for handling structure failed\n");
			;}
		return data;
	}
	
	return NULL;
}


void *mm_calloc(int type, size_t times, size_t sz, char *file, int line)
{
	void *data = calloc(times,sz);
	if(data)
	{
		memory_allocation *allocation = (memory_allocation *)malloc(sizeof(memory_allocation));
		if(allocation)
		{
			/* allocate filename (it's on the stack right now) */
			char *filename = NULL;
			int size = strlen(file);
			filename = (char *)calloc(size+1, sizeof(char));
			mstat[type].alloc_times++;
			mstat[type].alloc_size+=sz;
			memcpy(filename, file, size + 1);
			/* fill the allocation data */
			allocation->pt = data;
			allocation->file = filename;
			allocation->line = line;
			allocation->size = sz*times;
			allocation->loop_back = &mstat[type];
			bstree_add(&mstat[type].mm_root, (void *)allocation, mm_compare);
			printf("[MM] Alloc'ed %d bytes at %s:%d point:%p\n",allocation->size,allocation->file,allocation->line,allocation);
		}
		else 
			printf("[MM] Allocation for handling structure failed\n");
		return data;
	}
	
	return NULL;
}

void mm_free(int type, void *pt)
{
	if(pt)
	{
		memory_allocation toSearch;
		toSearch.pt = pt;
		bstree_delete(&mstat[type].mm_root, &toSearch, mm_compare, mm_free_struct);
		mstat[type].alloc_times--;
		free(pt);
	}
	
	return;
}
/*
void mm_stats()
{
	mm_nbofallocs=0;
	mm_sizeofallocs=0;
	printf("################################################\n");
	printf("################ MEMORY MANAGER ################\n");
	printf("################################################\n");
	printf("################# Allocations: #################\n");	
	printf("################################################\n");

	bstree_walk(mm_root, mm_print_func);
	
	printf("################################################\n");
	printf("#       Nb. of allocs: %8d                #\n",mm_nbofallocs);
	printf("#          Total size: %8d bytes          #\n",mm_sizeofallocs);
	printf("################################################\n");

}

*/



