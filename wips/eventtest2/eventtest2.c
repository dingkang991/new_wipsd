#include <stdio.h>
#include "eventtest2.h"

void* init_test(void);
void* pBeaconTest(core2EventLib_t * tmp);
void* getEventReturn(void);

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
	.eventLibName = "libtest2.so",
	.eventInfo = {
		.eventId = 2,
		.eventName = "test event222",
		.eventDescription = "test event discription"
	},
	.eventMem = {
		.memInitLen=10240,
		.memLen = 0,
		.memStart =NULL,
	},
	.wnodeMem = {
		.wnodeMemInitLen = 32,
	},
	.eventCB ={
		.eventCBInit = init_test,
		.pBeaconCB = pBeaconTest
	}
};

void* EventLibInfoReturn(void)
{
	;
	return (void*)&eventLibInfo;
}

void* pBeaconTest(core2EventLib_t* tmp)
{
													
	return NULL;
}


void* init_test(void)
{
	log_debug("at libtest222.so func(init_test) test\n");
	return NULL;
}

__attribute__((constructor)) void* insmod_func(void)
{

	log_debug("at libtest2.so will insmod\n");
	return NULL;
}

__attribute__((destructor)) void* rmmod_func(void)
{

	log_debug("at libtest2.so will rmmod\n");
	return NULL;
}



