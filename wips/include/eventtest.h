#ifndef __EVENT_TEST_H__
#define __EVENT_TEST_H__

#include "eventInfo.h"
#include "log.h"

#define log_info(format,...) LOG("test1",TEST1_LOG,0,LEVEL_INFO,format,  ##__VA_ARGS__)
#define log_debug(format,...) LOG("test1",TEST1_LOG,0,LEVEL_DEBUG,format,  ##__VA_ARGS__)
#define log_error(format,...) LOG("test1",TEST1_LOG,0,LEVEL_ERROR,format,  ##__VA_ARGS__)
#define log_warn(format,...) LOG("test1",TEST1_LOG,0,LEVEL_WARN,format,  ##__VA_ARGS__)


#endif

