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



struct wipsContext{
	struct list_head libEventList;
	struct list_head pBeaconList;
	struct list_head pDataList;
	wNodeMem_t memTotal;
	wNodeMemMap_t memMap[MODULE_MAX];
	int memMapOffset;
	wipsInterface_t wipsInterface;
	unsigned long packetCounter;
};

extern core2EventLib_t* core2EventLibInit(core2EventLib_t* core2EventLib,eventLibLinkInfo_t* eventLibInfo);
extern struct wipsContext ctx;



#endif
