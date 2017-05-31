#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "memory.h"
#include "main.h"
#include "nodeInfo.h"
#include "wipsInterface.h"
#include "confread.h"

int logType1= 0xffffffff;
int logType2= 0xffffffff;
int logLevel = 0;
struct wipsContext ctx;


memstat mstat [MODULE_MAX]; 

void ctxInit()
{
	memset(&ctx,0,sizeof(ctx));
	INIT_LIST_HEAD(&ctx.libEventList);
	INIT_LIST_HEAD(&ctx.pAllManageMentFrameList);
	INIT_LIST_HEAD(&ctx.pAssocationRequestList);
	INIT_LIST_HEAD(&ctx.pAssocationResponseList);
	INIT_LIST_HEAD(&ctx.pReassocationRequestList);
	INIT_LIST_HEAD(&ctx.pReassocationResponseList);
	INIT_LIST_HEAD(&ctx.pReassocationResponseList);
	INIT_LIST_HEAD(&ctx.pProbeRequestList);
	INIT_LIST_HEAD(&ctx.pProbeResponseList);
	INIT_LIST_HEAD(&ctx.pBeaconList);
	INIT_LIST_HEAD(&ctx.pATIMList);
	INIT_LIST_HEAD(&ctx.pDisassociationList);
	INIT_LIST_HEAD(&ctx.pAuthenticationList);
	INIT_LIST_HEAD(&ctx.pDeauthenicationList);
	INIT_LIST_HEAD(&ctx.pAllControlFrameList);
	INIT_LIST_HEAD(&ctx.pPowerSaveList);
	INIT_LIST_HEAD(&ctx.pRTSList);
	INIT_LIST_HEAD(&ctx.pCTSList);
	INIT_LIST_HEAD(&ctx.pACKList);
	INIT_LIST_HEAD(&ctx.pCFEndList);
	INIT_LIST_HEAD(&ctx.pCFEndACKList);
	INIT_LIST_HEAD(&ctx.pDataList);
	INIT_LIST_HEAD(&ctx.wNodeBSS);
	INIT_LIST_HEAD(&ctx.wNodeSta);

	if ((ctx.wNodeAllHash = hash_new()) == NULL){
		log_error("hash_new failed");
		return -1;
	}
	
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
	ctx.memMap[tmp->eventLibInfo.eventInfo.eventId].module = tmp;
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
		

	if (tmp->eventLibInfo.eventCB.pAllManagementFrameCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pAllManagementFrameList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pAllManagementFrameCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pAllManageMentFrameList);
		}else{
			log_error("module[%s] regist cb to pAllManagementFrameList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}
		
	if (tmp->eventLibInfo.eventCB.pAssocationRequestCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pAssocationRequestList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pAssocationRequestCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pAssocationRequestList);
		}else{
			log_error("module[%s] regist cb to pAssocationRequestList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pAssocationResponseCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pAssocationResponseList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pAssocationResponseCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pAssocationResponseList);
		}else{
			log_error("module[%s] regist cb to pAssocationResponseList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pReassocationRequestCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pReassocationRequestList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pReassocationRequestCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pReassocationRequestList);
		}else{
			log_error("module[%s] regist cb to pReassocationRequestList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pReassocationResponseCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pReassocationResponseList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pReassocationResponseCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pReassocationResponseList);
		}else{
			log_error("module[%s] regist cb to pReassocationResponseList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pProbeRequestCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pProbeRequestList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pProbeRequestCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pProbeRequestList);
		}else{
			log_error("module[%s] regist cb to pProbeRequestList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pProbeResponseCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pProbeResponseList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pProbeResponseCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pProbeResponseList);
		}else{
			log_error("module[%s] regist cb to pProbeResponseList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
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

		
	if (tmp->eventLibInfo.eventCB.pATIMCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pATIMCB\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pATIMCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pATIMList);
		}else{
			log_error("module[%s] regist cb to pATIMCB error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pDisassociationCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pDisassociationList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pDisassociationCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pDisassociationList);
		}else{
			log_error("module[%s] regist cb to pDisassociationList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pAuthenticationCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pAuthenticationList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pAuthenticationCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pAuthenticationList);
		}else{
			log_error("module[%s] regist cb to pAuthenticationList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

	if (tmp->eventLibInfo.eventCB.pDeauthenicationCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pDeauthenicationList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pDeauthenicationCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pDeauthenicationList);
		}else{
			log_error("module[%s] regist cb to pDeauthenicationList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

	if (tmp->eventLibInfo.eventCB.pAllControlFrameCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pAllControlFrameCB\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pAllControlFrameCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pAllControlFrameList);
		}else{
			log_error("module[%s] regist cb to pAllControlFrameCB error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

	if (tmp->eventLibInfo.eventCB.pPowerSaveCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pPowerSaveList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pPowerSaveCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pPowerSaveList);
		}else{
			log_error("module[%s] regist cb to pPowerSaveList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

	if (tmp->eventLibInfo.eventCB.pRTSCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pRTSList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pRTSCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pRTSList);
		}else{
			log_error("module[%s] regist cb to pRTSList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}


		
	if (tmp->eventLibInfo.eventCB.pCTSCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pCTSList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pCTSCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pCTSList);
		}else{
			log_error("module[%s] regist cb to pCTSList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pACKCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pACKList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pACKCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pACKList);
		}else{
			log_error("module[%s] regist cb to pACKList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pCFEndCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pCFEndList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pCFEndCB,tmp);
		if(funcTmp != NULL)
		{
			list_add(&(funcTmp->list),&ctx.pCFEndList);
		}else{
			log_error("module[%s] regist cb to pCFEndList error\n",tmp->eventLibInfo.eventLibName);
		}
		
	}

		
	if (tmp->eventLibInfo.eventCB.pCFEndACKCB != NULL)
	{
		funcCB_t *funcTmp;
		log_info("module[%s] regist cb to pCFEndACKList\n",tmp->eventLibInfo.eventLibName);
		funcTmp = initFuncCB(tmp->eventLibInfo.eventCB.pCFEndACKCB,tmp);
		if(funcTmp != NULL)
		{	
			list_add(&(funcTmp->list),&ctx.pCFEndACKList);
		}else{
			log_error("module[%s] regist cb to pCFEndACKList error\n",tmp->eventLibInfo.eventLibName);
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
		
eventLibLinkInfo_t* insmodModule(struct confread_section *path)
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
		log_error("new eventLibLinkInfo for \"%s\" is NULL\n",path->name);
		return -1;
	}
	log_info("insmod module path:%s\t\n",path->name);

	snprintf(eventLibLinkInfoTmp->eventLibAbsPath,EVENTLIB_ABS_PATH_MAX,"%s",path->name);
	
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
	eventLibLinkInfoTmp->initCBFun=func;
	memcpy(&eventLibLinkInfoTmp->eventLibInfo,eventLibInfoTmp,sizeof(eventLibInfo_t));
	
	//log_debug("get event lib name:%s\n",eventLibLinkInfoTmp->eventLibInfo.eventLibName);
	//log_debug("run eventCB.eventCBInit\n");
	if(eventLibLinkInfoTmp->eventLibInfo.eventCB.eventCBInit != NULL){
		char* configValue = NULL;
		configValue = confread_find_value(path,"baseConfig");
		if(configValue != NULL)
		{
			log_info("baseConfig (%s),for module (%s)\n",configValue,path->name);
		}else{
			log_info("baseConfig (%s),for modeule (%s)\n","null",path->name);
		eventLibLinkInfoTmp->eventLibInfo.eventCB.eventCBInit(configValue);
	}
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
	if(tmp->wNodeBssid != NULL)
	{
		tmp->wNodeBssid->memPayload2LibEventLen = tmp->wNodeBssid->memInfo.memMap[eventLibInfo->eventLibInfo.eventInfo.eventId].memLen;
		if(tmp->wNodeBssid->memPayload2LibEventLen != 0)
			tmp->wNodeBssid->memPayload2LibEvent = tmp->wNodeBssid->memInfo.memStart + tmp->wNodeBssid->memInfo.memMap[eventLibInfo->eventLibInfo.eventInfo.eventId].memOffset;
		else
			tmp->wNodeBssid->memPayload2LibEvent = NULL;
	}

	if(tmp->wNodeSta != NULL)
	{
		tmp->wNodeSta->memPayload2LibEventLen = tmp->wNodeSta->memInfo.memMap[eventLibInfo->eventLibInfo.eventInfo.eventId].memLen;
		if(tmp->wNodeSta->memPayload2LibEventLen != 0)
			tmp->wNodeSta->memPayload2LibEvent = tmp->wNodeSta->memInfo.memStart + tmp->wNodeSta->memInfo.memMap[eventLibInfo->eventLibInfo.eventInfo.eventId].memOffset;
		else
			tmp->wNodeSta->memPayload2LibEvent = NULL;
	}

	return tmp;
}

MM_STATS(CORE_ID);


void loadBaseConfig()
{
	struct confread_section* root=NULL;
	char* configValue = NULL;
	if(ctx.configFile == NULL)
	{
		log_error("config File is NULL,can not load base config\n");
		return;
	}

	root = confread_find_section(ctx.configFile,"root");

	/*****logtype1******/
	configValue = confread_find_value(root,"logType1");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default 0xffffffff\n","logtype1");
		logType1 = 0xffffffff;
	}else{
		log_info("find key(%s),value(%s)\n","logType1",configValue);
		sscanf(configValue,"%x",&logType1);
		//logType1 = atoi(configValue);
	}

	/*****logtype2******/
	configValue = confread_find_value(root,"logType2");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default 0xffffffff\n","logtype2");
		logType1 = 0xffffffff;
	}else{
		log_info("find key(%s),value(%s)\n","logType2",configValue);
		sscanf(configValue,"%d",&logType2);
	}

	/*****logLevel******/
	configValue = confread_find_value(root,"logLevel");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default 3\n","logLevel");
		logType1 = 0xffffffff;
	}else{
		log_info("find key(%s),value(%s)\n","logLevel",configValue);
		sscanf(configValue,"%d",&logLevel);
	}

	
	/*****againgTime******/
	configValue = confread_find_value(root,"againgTime");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default 30\n","againgTime");
		ctx.againgTime = 30;
	}else{
		log_info("find key(%s),value(%s)\n","againgTime",configValue);
		sscanf(configValue,"%d",&ctx.againgTime);
	}

	/*****travelsalTime******/
	configValue = confread_find_value(root,"traversalTime");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default 60\n","travelsalTime");
		ctx.traversalTime = 60;
	}else{
		log_info("find key(%s),value(%s)\n","travelsalTime",configValue);
		sscanf(configValue,"%d",&ctx.traversalTime);
	}

	
	/*****thrift server ip******/
	configValue = confread_find_value(root,"serverIp");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default localhost\n","serverIp");
		snprintf(ctx.serverIp,SERVER_IP_STR_LEN,"%s","localhost");
	}else{
		log_info("find key(%s),value(%s)\n","serverIp",configValue);
		sscanf(configValue,"%s",ctx.serverIp);
	}

	
	/*****thrift server ip******/
	configValue = confread_find_value(root,"serverPort");
	if(configValue == NULL)
	{
		log_error("can not load config key(%s) ,load default 9091\n","serverPort");
		ctx.serverPort = 9091;
	}else{
		log_info("find key(%s),value(%s)\n","serverPort",configValue);
		sscanf(configValue,"%d",&ctx.serverPort);
	}

	return;
}

void loadAllModules()
{
	struct confread_section *thisSect = NULL;
	struct confread_pair *thisPair = NULL;
	char* configValue = NULL;
	if(ctx.configFile == NULL)
	{
		log_error("config file is NULL\n");
		return;
	}
	
	thisSect = ctx.configFile->sections;

	while (thisSect) {
		int ret = 0;
		log_info("load wips module[%s]\n",thisSect->name);
		
		ret = insmodModule(thisSect);

		if(ret != 0)
		{
			log_error("insmod module[%s] error ,pls check\n",thisSect->name);
		}else{
			log_info("insmode module[%s] success\n",thisSect->name);
		}
		thisPair = thisSect->pairs;

		while (thisPair) {

//			printf("%s = %s\n", thisPair->key, thisPair->value);
			thisPair = thisPair->next;

		}
		thisSect = thisSect->next;

	}
}

void main(int argc ,char** argv)
{
	int ch;
	opterr = 0;
	
	ctxInit();
	while((ch = getopt(argc, argv, "a:b:l:f:h")) != -1)
	switch(ch)
	{
		case 'h':
			log_debug("option h,debug hash\n");
			main_hash();
			break;
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
		case 'f':
			log_debug("read config file:'%s'\n",optarg);
			if (!(ctx.configFile = confread_open(optarg))) {
					log_error("Config(%s) open failed\n",optarg);
					return -1;
			}
			
			log_info("----------------stage(load config)-----------------\n");
			loadBaseConfig();
			
			log_info("----------------stage(load config)-----------------\n");
			loadAllModules();
			
			break;
		default:
			printf("other option :%c\n", ch);
	}
//	inorder_avltree(NULL);

	/*
	printf("logType:%d\n",logType1);
	printf("logType:%d\n",logType2);
	printf("logLevel:%d\n",logLevel);

	log_debug("logType1:%x\n",logType1);
	log_debug("logType2:%x\n",logType2);
	log_debug("logLevel:%x\n",logLevel);
*/
	eventLibLinkInfo_t* tmp;
	uloop_init();/*
	insmodModule("./libtest.so");
	insmodModule("./libtest2.so");
*/

	log_error("----------------test code-----------------\n");
	/*
	{
	char beaconBuf[30]={0x80,0x00,0x0,0x0,0xff,0xff,0xff,0xff,0xff,0xff,\
	0x11,0x11,0x11,0x11,0x11,0x11,\
	0x11,0x11,0x11,0x11,0x11,0x11,\
	0x00,0x00,\
	0x22,0x22,0x22,0x22,0x22,0x22\
	};
	
	core2EventLib_t info2Event;
	//INIT_CORE2EVENTLIB_TMP(pBeacon);
	memset(&info2Event,0,sizeof(core2EventLib_t));
	info2Event.wNodeSta = NULL;
	info2Event.wNodeBssid = NULL;
	//info2Event.proberInfo.fd = fd;
	freshTime();
	wipsd_handle_wlansniffrm(beaconBuf, 30, &info2Event);
	
	log_error("----------------test code again-----------------\n");
 	wipsd_handle_wlansniffrm(beaconBuf, 30, &info2Event);
 	log_error("_________________over______________________\n");
	return 0;
					
}
*/
/*
	wNode_t* tmpWnode = initWnode(NULL);
	core2EventLib_t pBeacon,pData;
	snprintf(pBeacon.tmpInfo,128,"Beacon packet will comming");
	snprintf(pData.tmpInfo,128,"Data packet will comming");
	pBeacon.wNodeBssid= tmpWnode ;
	
	handleAllCB(&ctx.pBeaconList,&pBeacon);
	
	handleAllCB(&ctx.pBeaconList,&pBeacon);
	log_error("----------------split data-----------------\n");
	handleAllCB(&ctx.pDataList,&pData);
	log_error("++++++++++++++++++core  ++++++++++++++++++++\n");

	mm_stats(CORE_ID);
	log_error("++++++++++++++++++core over+++++++++++++++++++++\n");

	*/
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
	
	
	
