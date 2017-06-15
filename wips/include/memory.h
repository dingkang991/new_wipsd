#ifndef __MEMORY_H__
#define __MEMORY_H__
#include "bstree.h"

#define MM_STATS(TYPE)  \
unsigned long mm_nbofallocs_##TYPE=0;\
unsigned long mm_sizeofallocs_##TYPE=0;\
static void mm_print_func_ ## TYPE( void *data)\
{\
	memory_allocation *alloc = (memory_allocation *)data;\
	if(alloc)\
	{\
		log_debug("@0x%08x:\t%s:%d\t:\t%d bytes@\n",\
			   (unsigned int)alloc->pt,\
			   alloc->file,\
			   alloc->line,\
			   alloc->size);\
		mm_nbofallocs_ ## TYPE++;\
		mm_sizeofallocs_ ## TYPE+=alloc->size;\
	}\
}\
void mm_stats_tmp_ ## TYPE()\
{\
	mm_nbofallocs_ ## TYPE=0;\
	mm_sizeofallocs_ ## TYPE=0;\
	log_debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");\
	log_debug("@@@@@@@@@@@@@@@@ MEMORY MANAGER @@@@@@@@@@@@@@@@\n");\
	log_debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");\
	log_debug("@@@@@@@@@@@@@@@@@ Allocations: @@@@@@@@@@@@@@@@@\n");\
	log_debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");\
	bstree_walk(mstat[CORE_ID].mm_root, mm_print_func## _ ## TYPE);\
	log_debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");\
	log_debug("@       Nb. of allocs: %8d                @\n",mm_nbofallocs_ ## TYPE);\
	log_debug("@          Total size: %8d bytes          @\n",mm_sizeofallocs_ ## TYPE);\
	log_debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");\
	log_debug("@       Nb. of allocs: %8d                @\n",mstat[LIBEVENT_TEST_ID].alloc_times);\
	log_debug("@          Total size: %8d bytes          @\n",mstat[LIBEVENT_TEST_ID].alloc_size);\
	log_debug("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");\
}

#define mm_stats(TYPE) mm_stats_tmp_ ## TYPE()


typedef struct _memstat
{
  char *name;
  unsigned long alloc_times;
  unsigned long diff;
  unsigned long alloc_size;
  struct bstree_node *mm_root;
}memstat;

typedef struct _memory_allocation{
	char *file;
	unsigned int  line;
	
	void *pt;
	void *loop_back;
	unsigned int size;
}memory_allocation;


#define MM_MALLOC(id,a) mm_malloc((id),(a),__FILE__,__LINE__)
#define MM_CALLOC(id,a,b) mm_calloc((id),(a),(b),__FILE__,__LINE__)
#define MM_FREE(id,a) mm_free((id),(a))



extern void *mm_malloc(int type,size_t sz, char *file, int line);
extern void *mm_calloc(int type,size_t times, size_t sz, char *file, int line);
extern void mm_free( int type,void *pt);
//extern void mm_stats(void);



#endif
