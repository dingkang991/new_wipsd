#include <stdio.h>
#include <stdlib.h>
#include "eventInfo.h"
#include "memory.h"
#include "main.h"


wNode_t* initWnode(wNode_t* node)
{
	wNode_t* tmp = NULL;
	int i = 0;
	if(node == NULL)
	{
		tmp = (wNode_t*) MM_MALLOC(CORE_ID,sizeof(wNode_t));
	}else{
		tmp = node;
	}
	if (tmp == NULL)
	{
		log_error("initWnode error , tmp is NULL\n");
		return NULL;
	}

	memset(tmp,0,sizeof(wNode_t));

	tmp->memInfo.memStart = MM_MALLOC(CORE_ID,ctx.memTotal.memLen);
	tmp->memInfo.memLen = ctx.memTotal.memLen;
	tmp->memInfo.memMap = ctx.memMap;
	memset(tmp->memInfo.memStart,0,tmp->memInfo.memLen);
	for(i = 1 ;i <MODULE_MAX;i++)
	{
		wNodeMemMap_t* libModule = (eventLibLinkInfo_t*)&ctx.memMap[i];
		eventLibLinkInfo_t* module = (eventLibLinkInfo_t*) libModule->module;
		if (module == NULL)
			continue;
		if(module->eventLibInfo.wnodeMem.wNodeMemInitCB != NULL)
			module->eventLibInfo.wnodeMem.wNodeMemInitCB((void*)tmp->memInfo.memStart+libModule->memOffset,libModule->memLen);
	}
		
	tmp->initFlag = 1;
	setTimeNow(&tmp->upTime);
//	setTimeNow(&node->lastTime);

	return tmp;

}

int destroyWnode(wNode_t* node,int is_free)
{
	int i = 0;
	if (node == NULL)
	{
		log_error("distroyWnode error , node is NULL\n");
		return -1;
	}
	
	for(i = 0 ;i <MODULE_MAX;i++)
	{
		wNodeMemMap_t* libModule = (eventLibLinkInfo_t*)&ctx.memMap[i];
		eventLibLinkInfo_t* module = (eventLibLinkInfo_t*) libModule->module;
		if(module->eventLibInfo.wnodeMem.wNodeMemDestroyCB != NULL)
			module->eventLibInfo.wnodeMem.wNodeMemDestroyCB((void*)node->memInfo.memStart+libModule->memOffset,libModule->memLen);
	}
	

	MM_FREE(CORE_ID,node->memInfo.memStart);

	if(is_free!=0)
		MM_FREE(CORE_ID,node);

	return 0;

}



