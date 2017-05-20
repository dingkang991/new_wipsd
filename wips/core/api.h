#ifndef __EVENT_INFO__
#define __EVENT_INFO__
#include "log.h"

#define log_info_api(format,...) LOG("API",API,0,LEVEL_INFO,format,  ##__VA_ARGS__)
#define log_debug_api(format,...) LOG("API",API,0,LEVEL_DEBUG,format,  ##__VA_ARGS__)
#define log_error_api(format,...) LOG("API",API,0,LEVEL_ERROR,format,  ##__VA_ARGS__)
#define log_warn_api(format,...) LOG("API",API,0,LEVEL_WARN,format,  ##__VA_ARGS__)


typedef struct eventReport_s{
	int eventId;
	char eventDesc[256];
	char mac[ETH_STR_ALEN];
	char peerMac[ETH_STR_ALEN];
} eventReport_t;


#endif

