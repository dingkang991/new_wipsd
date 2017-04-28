#ifndef __EVENT_INFO__
#define __EVENT_INFO__
#include "list.h"
#include "nodeInfo.h"
#include "common.h"

#define EVENT_NAME_MAX 64
#define EVENTLIB_NAME_MAX 64
#define EVENTLIB_ABS_PATH_MAX 512
#define EVENT_DESCRIPTION_MAX 256

#define USER_MEM(_tmp) (_tmp->eventInfoCore->eventLibInfo.eventMem.memStart)

typedef void* (*INIT_CB_FUNC)();

enum
{
	LIBEVENT_TEST_ID = 1,		
	LIBEVENT_TEST2_ID = 2,
	CORE_ID = 3,
	MODULE_MAX
};



typedef struct eventInfo_s{
	int eventId;
	char eventName[EVENT_NAME_MAX];
	char eventDescription[EVENT_DESCRIPTION_MAX];
} eventInfo_t;

typedef struct eventLibMemInfo_s{
	int memInitLen;
	int memLen;
	void* memStart;
}eventLibMemInfo_t;

typedef struct eventLibWnodeMemInfo_s{
	int wnodeMemInitLen;
//	int wnodeMemLen;
//	void* WnodeMemStart;
}eventLibWnodeMemInfo_t;



typedef struct eventCB_s{
	void (*eventCBInit)();
	/***********Management Frame(type 00)***********/
	void (*pAllManagementFrameCB)(void*); 
	void (*pAssocationRequestCB)(void*);//0000
	void (*pAssocationResponseCB)(void*);//0001
	void (*pReassocationRequestCB)(void*);//0010
	void (*pReassocationResponseCB)(void*);//0011
	void (*pProbeRequestCB)(void*);//0100
	void (*pProbeResponseCB)(void*);//0101
	void (*pBeaconCB)(void*);//1000
	void (*pATIMCB)(void*);//1001
	void (*pDisassociationCB)(void*);//1010
	void (*pAuthenticationCB)(void*);//1011
	void (*pDeauthenicationCB)(void*);//1100
	/*********Control Frame(type 01)***********/
	void (*pAllControlFrameCB)(void*);
	void (*pPowerSaveCB)(void*);//1010
	void (*pRTSCB)(void*);//1011
	void (*pCTSCB)(void*);//1100
	void (*pACKCB)(void*);//1101
	void (*pCFEndCB)(void*);//1110
	void (*pCFEndACKCB)(void*);//1111
	/*********Data Frame(type 10)************/
	void (*pDataCB)(void*);
}eventCB_t;


//getEventReturn 函数返回数据结构
typedef struct eventLibInfo_s{
	char eventLibName[EVENTLIB_NAME_MAX];
	eventLibMemInfo_t eventMem;
	eventLibWnodeMemInfo_t wnodeMem;
	eventCB_t eventCB;
	eventInfo_t eventInfo;
}eventLibInfo_t;


typedef struct eventLibLinkInfo_s{
	char eventLibAbsPath[EVENTLIB_ABS_PATH_MAX];
	void *DlHandler;
	INIT_CB_FUNC initCBFun;
	struct list_head list;
	eventLibInfo_t eventLibInfo;
}eventLibLinkInfo_t;

typedef struct core2EventLib_s{
	char tmpInfo[128];
	eventLibLinkInfo_t* eventInfoCore;
	eventLibMemInfo_t* eventMemCore;

	proberInfo_t proberInfo;
	radioInfo_t radioInfo;
	wNode_t* wNodeSta;
	wNode_t* wNodeBssid;
	struct ieee80211_frame *wh;
	int whLen;
}core2EventLib_t;

#define INIT_CORE2EVENTLIB_TMP(_name) \
	core2EventLib_t _name;\
	eventLibLinkInfo_t eventLibLinkInfoTmp_##_name;\
	eventLibMemInfo_t eventMemCoreTmp_##_name;\
	wNode_t wNodeTmp_##_name;\
	wNodeMem_t wNodeMemTmp_##_name;\
	_name.eventInfoCore = &eventLibLinkInfoTmp_##_name;\
	_name.eventMemCore = &eventMemCoreTmp_##_name;\
	_name.wNode = &wNodeTmp_##_name;\
	_name.payLoad = &wNodeMemTmp_##_name;

#define DESTROY_CORE2EVENTLIB(_name) \
	MM_FREE(CORE_ID,_name.eventMemCore->memStart);


typedef struct funcCB_s{
	void (*func)(core2EventLib_t*);
	struct list_head list;
	eventLibLinkInfo_t * eventLibLinkInfo;
}funcCB_t;

#endif

