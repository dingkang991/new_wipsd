#ifndef __API_H__
#define __API_H__
#include "log.h"
#include "nodeInfo.h"
#include "eventInfo.h"

#define log_info_api(format,...) LOG("API",API,0,LEVEL_INFO,format,  ##__VA_ARGS__)
#define log_debug_api(format,...) LOG("API",API,0,LEVEL_DEBUG,format,  ##__VA_ARGS__)
#define log_error_api(format,...) LOG("API",API,0,LEVEL_ERROR,format,  ##__VA_ARGS__)
#define log_warn_api(format,...) LOG("API",API,0,LEVEL_WARN,format,  ##__VA_ARGS__)

typedef struct eventReport_s{
	int eventId;
	char eventInfo[DESCSTRLEN];
	char eventDesc[DESCSTRLEN];
	wNode_t *node;
	wNode_t *nodeP;
	eventLibInfo_t* eventLib;
} eventReport_t;


#endif

