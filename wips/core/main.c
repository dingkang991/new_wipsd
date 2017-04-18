#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "memory.h"
#include "main.h"
#include "nodeInfo.h"
#include "wipsInterface.h"

int logType1= 0xffffffff;
int logType2= 0xffffffff;
int logLevel = 0;
struct wipsContext ctx;


memstat mstat [MODULE_MAX]; 

void ctxInit()
{
	memset(&ctx,0,sizeof(ctx));
	INIT_LIST_HEAD(&ctx.libEventList);
	INIT_LIST_HEAD(&ctx.pBeaconList);
	INIT_LIST_HEAD(&ctx.pDataList);
	memset(&ctx.memTotal,0,sizeof(wNodeMem_t));
	memset(ctx.memMap,0,(sizeof(wNodeMemMap_t)*MODULE_MAX));
	ctx.memTotal.memMap = ctx.memMap;
	ctx.memMapOffset = 0;
	ctx.packetCounter = 0;
}

INIT_CB_FUNC invokeMethod( eventLibLinkInfo_t* eventLibLinkInfo)
{
	void *dl_handle;
	INIT_CB_FUNC func;
	char *error;

	if(eventLibLinkInfo->DlHandler != NULL)
	{
		log_error("path:%s was linked,return\t\n");
		return NULL;
	}

	/* Open the shared object */
	dl_handle = dlopen( eventLibLinkInfo->eventLibAbsPath, RTLD_NOW  );
	if (!dl_handle) {
	log_error( "!!! %s\n", dlerror() );
	return NULL;
	}

	/* Resolve the symbol (method) from the object */
	func = dlsym( dl_handle, "EventLibInfoReturn" );
	error = dlerror();
	if (error != NULL) {
	log_error( "!!! %s\n", error );
	return NULL;
	}

	/* Call the resolved method and print the result */
	log_debug("get sync lib cb:%p\n", func );

	/* Close the object */
	//dlclose( dl_handle );
	eventLibLinkInfo->DlHandler = dl_handle;
	return func;
}

eventLibLinkInfo_t* eventLibLinkInfoNew()
{
	eventLibLinkInfo_t* tmp;
	tmp = calloc(1,sizeof(eventLibLinkInfo_t));
	if(tmp == NULL)
	{
		log_error("calloc error\n");
		return NULL;
	}

	INIT_LIST_HEAD(&tmp->list);
	return tmp;
}
funcCB_t* funcCBNew()
{
	funcCB_t* tmp;
	tmp = calloc(1,sizeof(funcCB_t));
	if(tmp == NULL)
	{
		log_error("calloc error\n");
		return NULL;
	}
	INIT_LIST_HEAD(&tmp->list);
	return tmp;
}

funcCB_t* initFuncCB(void (*FuncCBTmp)(core2EventLib_t*),eventLibLinkInfo_t* eventLibLinkInfoTmp)
{
	funcCB_t *tmp;
	tmp = funcCBNew();
	if(tmp == NULL)
	{
		return NULL;
	}
	tmp->func = FuncCBTmp;
	tmp->eventLibLinkInfo = eventLibLinkInfoTmp;
	return tmp;
}

void* callocMemForLibEvent(eventLibMemInfo_t* tmp)
{
	if(!tmp && !tmp->memInitLen)
	{
		return NULL;
	}

	tmp->memStart = calloc(tmp->memInitLen,1);
	if(tmp->memStart == NULL)
	{
		log_error("colloc memory for Libevent error\n");
		return NULL;
	}
	tmp->memLen = tmp->memInitLen;
	return tmp->memStart;

}

int parseWnodeInfo2CTX(eventLibLinkInfo_t* tmp)
{
	if(NULL == tmp)
		return -1;
	if(tmp->eventLibInfo.wnodeMem.wnodeMemInitLen == 0)
	{
		log_info("module[%s] need not regist wnode mem\n",tmp->eventLibInfo.eventLibName);
		return 0;
	}
	log_info("module[%s] regist wnode mem %d to mem map ofset:%d \n",tmp->eventLibInfo.eventLibName,tmp->eventLibInfo.wnodeMem.wnodeMemInitLen,ctx.memMapOffset);
	ctx.memMap[tmp->eventLibInfo.eventInfo.eventId].memLen = tmp->eventLibInfo.wnodeMem.wnodeMemInitLen;
	ctx.memMap[tmp->eventLibInfo.eventInfo.eventId].memOffset = ctx.memMapOffset;
	ctx.memMapOffset += tmp->eventLibInfo.wnodeMem.wnodeMemInitLen;
	ctx.memTotal.memLen += tmp->eventLibInfo.wnodeMem.wnodeMemInitLen;
	return 0;
}
		
int parseCB2CTX(eventLibLinkInfo_t* tmp)
{
	if (NULL == tmp)
		return -1;
	if (tmp->eventLibInfo.eventCB.pBeaconCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pBeacon\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pBeaconCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pBeaconList);
		}else{
			log_error("module[%s] regist cb to pBeacon error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

	if (tmp->eventLibInfo.eventCB.pDataCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pdata\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pDataCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pDataList);
		}else{
			log_error("module[%s] regist cb to pBeacon error\n",tmp->eventLibInfo.eventLibName);
		}
	}
	return 0;
}
		
eventLibLinkInfo_t* insmodModule(char* path)
{
	INIT_CB_FUNC func;
	eventLibInfo_t *eventLibInfoTmp=NULL;
	eventLibLinkInfo_t* eventLibLinkInfoTmp=eventLibLinkInfoNew();
	if(NULL == path)
	{
		log_error("func(%s),path is NULL return -1\n",__func__);
		return -1;
	}
	
	if(NULL == eventLibLinkInfoTmp)
	{
		log_error("new eventLibLinkInfo for \"%s\" is NULL\n",path);
		return -1;
	}
	log_info("insmod module path:%s\t\n",path);

	snprintf(eventLibLinkInfoTmp->eventLibAbsPath,EVENTLIB_ABS_PATH_MAX,"%s",path);
	
	func=invokeMethod(eventLibLinkInfoTmp);
	
	log_debug("func(%s),get sync lib cb:%p\n",__func__, func);

	if(func == NULL)
	{/*
		printf("func(%s), eventLibInfo cb is NULL,return -2\n",__func__);
		return -2;
		*/
		log_error("func(%s),eventLibInfo cb is NULL, return -2\n",__func__);
		return -2;
	}
	eventLibInfoTmp=(eventLibInfo_t*)func();
	eventLibLinkInfoTmp->initCBFun=func();
	memcpy(&eventLibLinkInfoTmp->eventLibInfo,eventLibInfoTmp,sizeof(eventLibInfo_t));
	
	//log_debug("get event lib name:%s\n",eventLibLinkInfoTmp->eventLibInfo.eventLibName);
	//log_debug("run eventCB.eventCBInit\n");
	eventLibLinkInfoTmp->eventLibInfo.eventCB.eventCBInit();

	list_add(&ctx.libEventList,&eventLibLinkInfoTmp->list);
	parseCB2CTX(eventLibLinkInfoTmp);
	parseWnodeInfo2CTX(eventLibLinkInfoTmp);
	if(callocMemForLibEvent(&eventLibLinkInfoTmp->eventLibInfo.eventMem))
	{
		log_debug("clloc memory for:%s,start:%p,len:%d\n",eventLibLinkInfoTmp->eventLibInfo.eventLibName,\
															eventLibLinkInfoTmp->eventLibInfo.eventMem.memStart,\
															eventLibLinkInfoTmp->eventLibInfo.eventMem.memLen);
	}else{
	
		log_debug("clloc memory fail for:%s,start:%p,len:%d\n",eventLibLinkInfoTmp->eventLibInfo.eventLibName,\
														eventLibLinkInfoTmp->eventLibInfo.eventMem.memStart,\
														eventLibLinkInfoTmp->eventLibInfo.eventMem.memLen);
	}
	return 0;
}

void handleAllCB(struct list_head* CBList,core2EventLib_t *CBParam)
{
	struct list_head* tmp;
	funcCB_t* funcCBTmp=NULL;
	
	list_for_each(tmp,CBList)
	{
		
		funcCBTmp = list_entry(tmp,funcCB_t,list);
		
		if(funcCBTmp && funcCBTmp->func)
		{
			funcCBTmp->func(core2EventLibInit(CBParam,funcCBTmp->eventLibLinkInfo));
		}else{
			if(funcCBTmp->eventLibLinkInfo)
			{
				log_error("CBList error ,have NULL CB,eventname:%s\n",funcCBTmp->eventLibLinkInfo->eventLibInfo.eventLibName);
				//break;
			}else{
				log_error("CBList error,have NULL CB and eventLibLinkInfo is NULL\n");
			}
		}
			
	}

}

core2EventLib_t* core2EventLibInit(core2EventLib_t* core2EventLib,eventLibLinkInfo_t* eventLibInfo)
{
	core2EventLib_t *tmp;
	if(eventLibInfo == NULL)
	{
		log_error("core2EventLibInit params error\n");
		return NULL;
	}
	if(core2EventLib == NULL)
	{
		tmp = MM_CALLOC(CORE_ID,sizeof(core2EventLib_t),1);
		if(tmp == NULL)
		{
			log_error("calloc error");
			return NULL;
		}
	}else{
		tmp = core2EventLib;
	}
	//memset(tmp,0,sizeof(core2EventLib_t));

	tmp->eventInfoCore = eventLibInfo;
	tmp->eventMemCore = &eventLibInfo->eventLibInfo.eventMem;
	if(tmp->wNode != NULL)
	{
		tmp->payLoadLen = tmp->wNode->memInfo.memMap[eventLibInfo->eventLibInfo.eventInfo.eventId].memLen;
		if(tmp->payLoadLen != 0)
			tmp->payLoad = tmp->wNode->memInfo.memStart + tmp->wNode->memInfo.memMap[eventLibInfo->eventLibInfo.eventInfo.eventId].memOffset;
		else
			tmp->payLoad = NULL;
	}else{
		tmp->payLoadLen = 0;
		tmp->payLoad = 0;
	}
	return tmp;
}

MM_STATS(CORE_ID);

void main(int argc ,char** argv)
{
	int ch;
	opterr = 0;
	while((ch = getopt(argc, argv, "a:b:l:")) != -1)
	switch(ch)
	{
		case 'a':
			log_debug("option a:'%s'\n", optarg);
			sscanf(optarg,"%d",&logType1);
			break;
		case 'b':
			log_debug("option b:'%s'\n",optarg);
			sscanf(optarg,"%d",&logType2);
			break;
		case 'l':
			log_debug("option l:'%s'\n",optarg);
			logLevel=atoi(optarg);
			break;
		default:
			printf("other option :%c\n", ch);
	}
	inorder_avltree(NULL);

	/*
	printf("logType:%d\n",logType1);
	printf("logType:%d\n",logType2);
	printf("logLevel:%d\n",logLevel);

	log_debug("logType1:%x\n",logType1);
	log_debug("logType2:%x\n",logType2);
	log_debug("logLevel:%x\n",logLevel);
*/
	eventLibLinkInfo_t* tmp;
	uloop_init();
	ctxInit();
	insmodModule("./libtest.so");
	insmodModule("./libtest2.so");

	log_error("----------------split beacom-----------------\n");
	wNode_t* tmpWnode = initWnode(NULL);
	core2EventLib_t pBeacon,pData;
	snprintf(pBeacon.tmpInfo,128,"Beacon packet will comming");
	snprintf(pData.tmpInfo,128,"Data packet will comming");
	pBeacon.wNode = tmpWnode ;
	
	handleAllCB(&ctx.pBeaconList,&pBeacon);
	
	handleAllCB(&ctx.pBeaconList,&pBeacon);
	log_error("----------------split data-----------------\n");
	handleAllCB(&ctx.pDataList,&pData);
	log_error("++++++++++++++++++core  ++++++++++++++++++++\n");

	mm_stats(CORE_ID);
	log_error("++++++++++++++++++core over+++++++++++++++++++++\n");

	
	if(NULL ==setWipsInterface(&ctx.wipsInterface))
	{
		log_error("setWipsInterface error\n");
	}
	
	if(0==wipsInitSocket(&ctx.wipsInterface))
	{
		log_info("start uloop\n");
		uloop_run();
	}
	/*
	log_debug("log debug test\n");
	log_info("log info test\n");
	log_warn("log warn test\n");
	log_error("log error test\n");
	*/

//	AVLTreeTest();
//main_hash();
	}
	
	
	
