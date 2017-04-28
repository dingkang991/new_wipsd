#include <stdio.h>
#include <stdlib.h>
#include "eventInfo.h"
#include "memory.h"
#include "main.h"


wNode_t* initWnode(wNode_t* node)
{
	wNode_t* tmp = NULL;
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

	node->initFlag = 1;
	setTimeNow(&node->upTime);
//	setTimeNow(&node->lastTime);

	return tmp;

}

int distroyWnode(wNode_t* node,int is_free)
{

	if (node == NULL)
	{
		log_error("distroyWnode error , node is NULL\n");
		return -1;
	}

	MM_FREE(CORE_ID,node->memInfo.memStart);

	if(is_free!=0)
		MM_FREE(CORE_ID,node);

	return 0;

}



