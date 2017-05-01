#ifndef __MAIN_H__
#define __MAIN_H__

#include "eventInfo.h"
#include "nodeInfo.h"
#include "wipsInterface.h"
#include "log.h"


#define log_info(format,...) LOG("core",CORE,0,LEVEL_INFO,format,  ##__VA_ARGS__)
#define log_debug(format,...) LOG("core",CORE,0,LEVEL_DEBUG,format,  ##__VA_ARGS__)
#define log_error(format,...) LOG("core",CORE,0,LEVEL_ERROR,format,  ##__VA_ARGS__)
#define log_warn(format,...) LOG("core",CORE,0,LEVEL_WARN,format,  ##__VA_ARGS__)

#define log_info_wnode(format,...) LOG("core_wnode",CORE_WNODE,0,LEVEL_INFO,format,  ##__VA_ARGS__)
#define log_debug_wnode(format,...) LOG("core_wnode",CORE_WNODE,0,LEVEL_DEBUG,format,  ##__VA_ARGS__)
#define log_error_wnode(format,...) LOG("core_wnode",CORE_WNODE,0,LEVEL_ERROR,format,  ##__VA_ARGS__)
#define log_warn_wnode(format,...) LOG("core_wnode",CORE_WNODE,0,LEVEL_WARN,format,  ##__VA_ARGS__)



struct wipsContext{
	struct list_head libEventList;	
	struct list_head pAllManageMentFrameList;
	struct list_head pAssocationRequestList;
	struct list_head pAssocationResponseList;
	struct list_head pReassocationRequestList;
	struct list_head pReassocationResponseList;
	struct list_head pProbeRequestList;
	struct list_head pProbeResponseList;
	struct list_head pBeaconList;
	struct list_head pATIMList;
	struct list_head pDisassociationList;
	struct list_head pAuthenticationList;
	struct list_head pDeauthenicationList;
	struct list_head pAllControlFrameList;
	struct list_head pPowerSaveList;
	struct list_head pRTSList;
	struct list_head pCTSList;
	struct list_head pACKList;
	struct list_head pCFEndList;
	struct list_head pCFEndACKList;
	struct list_head pDataList;
	/*****wnode list******/
	struct list_head wNodeBSS;
	struct list_head wNodeSta;
	struct hash_control *wNodeAllHash;
	int againgTime;
	int traversalTime;
	time_t timeNow;
	time_t wNodeListTime;
	wNodeMem_t memTotal;
	wNodeMemMap_t memMap[MODULE_MAX];
	int memMapOffset;
	wipsInterface_t wipsInterface;
	unsigned long packetCounter;
	struct confread_file *configFile;
};

extern core2EventLib_t* core2EventLibInit(core2EventLib_t* core2EventLib,eventLibLinkInfo_t* eventLibInfo);
extern struct wipsContext ctx;



#endif
