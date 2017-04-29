#include <stdio.h>
#include "eventtest.h"
#include "memory.h"




void* initTest(void);
void* pBeaconTest(core2EventLib_t * tmp);
void* pDataTest(core2EventLib_t * tmp);
void* getEventReturn(void);

extern memstat mstat[MODULE_MAX];
/*
eventInfo_t eventInfo ={
	.eventId = 1,
	.eventName = "test event",
	.eventDescription = "test event discription"
};

eventCB_t eventCB ={
	.eventCBInit = init_test
};
*/

const eventLibInfo_t eventLibInfo ={
	.eventLibName = "libtest.so",
	.eventInfo = {
		.eventId = LIBEVENT_TEST_ID,
		.eventName = "test event",
		.eventDescription = "test event discription"
	},
	.eventMem = {
		.memInitLen=1024,
		.memLen = 0,
		.memStart =NULL,
	},
	.wnodeMem = {
		.wnodeMemInitLen = 4,
	},
	.eventCB ={
		.eventCBInit = initTest,
		.pBeaconCB = pBeaconTest,
		.pDataCB = pDataTest,
	}
};

#if 1
MM_STATS(LIBEVENT_TEST_ID)
#else
unsigned long mm_nbofallocs=0;
unsigned long mm_sizeofallocs=0;

static void mm_print_func( void *data)
{
	memory_allocation *alloc = (memory_allocation *)data;
	if(alloc)
	{
		log_debug("@0x%08x:\t%s:%d\t:\t%d bytes\n",
			   (unsigned int)alloc->pt,
			   alloc->file,
			   alloc->line,
			   alloc->size);
		mm_nbofallocs++;
		mm_sizeofallocs+=alloc->size;
	}
}


void mm_stats()
{

	mm_nbofallocs=0;
	mm_sizeofallocs=0;

	log_debug("################################################\n");
	log_debug("################ MEMORY MANAGER ################\n");
	log_debug("################################################\n");
	log_debug("################# Allocations: #################\n");	
	log_debug("################################################\n");

	bstree_walk(mstat[LIBEVENT_TEST_ID].mm_root, mm_print_func);
	
	log_debug("################################################\n");
	log_debug("#       Nb. of allocs: %8d                #\n",mm_nbofallocs);
	log_debug("#          Total size: %8d bytes          #\n",mm_sizeofallocs);
	log_debug("################################################\n");
	log_debug("#       Nb. of allocs: %8d                #\n",mstat[LIBEVENT_TEST_ID].alloc_times);
	log_debug("#          Total size: %8d bytes          #\n",mstat[LIBEVENT_TEST_ID].alloc_size);
	log_debug("################################################\n");

}
#endif


void* EventLibInfoReturn(void)
{
	;
	return (void*)&eventLibInfo;
}
void* initTest(void)
{

	log_debug("at libtest.so func(init_test) test\n");
	return NULL;
}

void* pBeaconTest(core2EventLib_t* tmp)
{
	wNode_t *bssid =NULL;
	if(tmp == NULL)
	{
		log_error("core2EventLib is NULL\n");
		return NULL;
	}

	bssid = tmp->wNodeBssid;
	if(bssid == NULL)
	{
		log_error("core2EventLib's wNodeBssid is NULL\n");
		return NULL;
	}

	int *flag =(int*) bssid->memPayload2LibEvent;
	int len = bssid->memPayload2LibEventLen;

	if(flag == NULL)
	{
		log_error("core2EventLib's bssid mempayload is NULL\n");
		return NULL;
	}

	if(*flag == 0)
	{
		log_info("____________bssid :"MACSTR" upline\n",MAC2STR(bssid->mac));
		*flag = 1;
	}else{
		log_info("____________bssid :"MACSTR" has been uplink\n",MAC2STR(bssid->mac));
	}
											
	return NULL;
}

void* pDataTest(core2EventLib_t* tmp)
{
	log_debug("get Data info form core to libevent is :%s\n",tmp->tmpInfo);
	return NULL;
}

__attribute__((constructor)) void* insmod_func(void)
{

log_debug("at libtest.so will insmod\n");
return NULL;
}

__attribute__((destructor)) void* rmmod_func(void)
{

log_debug("at libtest.so will rmmod\n");
log_debug("__________________test start__________\n");

//mm_stats(LIBEVENT_TEST_ID);
log_debug("__________________test end__________\n");

return NULL;
}



