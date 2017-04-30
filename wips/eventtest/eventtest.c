#include <stdio.h>
/*以下两个头文件必须引用*/
#include "eventtest.h"
#include "memory.h"

/*事件:检测ap上线,并输出bssid*/

/*事件内处理函数的声明*/
void* initTest(void);
void* pBeaconTest(core2EventLib_t * tmp);
void* pDataTest(core2EventLib_t * tmp);
void* getEventReturn(void);
/*内存检测模块使用,必须引用*/
extern memstat mstat[MODULE_MAX]; 

/*lib 库信息结构*/
const eventLibInfo_t eventLibInfo ={
	.eventLibName = "libtest.so",/*lib库名称*/
	.eventInfo = {/*lib 内事件信息结构定义*/
		.eventId = LIBEVENT_TEST_ID,/*事件ID,在主框架中头文件eventinfo.h中定义*/
		.eventName = "test event",/*事件名称*/
		.eventDescription = "test event discription"/*lib库检测事件的详细描述*/
	},
	.eventMem = {/*框架内使用内存管理,在lib库内尽量不要申请内存*/
/*这个结构定义了lib库内需要的内存大小.这个内存在每次回调到lib库时会传到lib库内的回调函数的参数内*/
		.memInitLen=1024,/*需要申请的内存大小*/
		.memLen = 0,/*框架使用,这里置0*/
		.memStart =NULL,/*所申请的内存*/
	},
	.wnodeMem = {/*每个sta或者bssid存储是使用wNode_t结构*/
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



