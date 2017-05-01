#ifndef __log_h__
#define __log_h__
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>


#define CORE		1<<0 // 1
#define AVL_TREE			1<<1 // 2
#define HASH				1<<2	 // 4
#define API					1<<3	 // 8
#define CORE_WNODE			1<<4	 // 16

#define TEST1_LOG			1<<10 // 1024
#define TEST2_LOG			1<<11 // 2048


extern int logType1;
extern int logType2;
extern int logLevel;

#define LEVEL_DEBUG    0  
#define LEVEL_TUNNINT  1  
#define LEVEL_INFO     2  
#define LEVEL_WARN     3  
#define LEVEL_ERROR    4

#ifndef LOG_INFO
#define LOG(module_str,userType1,userType2,userLevel,format, ...) \
do{\
	if((logType1&userType1 || logType2&userType2)	&& userLevel >= logLevel){\
    time_t t = time(0);\
    struct tm ttt = *localtime(&t);\
    fprintf(stdout, "[%10s]" format "",\
            module_str, ##__VA_ARGS__);}}while(0)
#else
#define LOG(module_str,userType1,userType2,userLevel,format, ...) \
do{\
	if((logType1&userType1 || logType2&userType2)	&& userLevel >= logLevel){\
    time_t t = time(0);\
    struct tm ttt = *localtime(&t);\
    fprintf(stdout, "[%10s][%11s] [%5d %4d-%02d-%02d %02d:%02d:%02d] [%s:%d] " format "",\
            module_str,#userLevel,getpid(), ttt.tm_year + 1900, ttt.tm_mon + 1, ttt.tm_mday, ttt.tm_hour,\
            ttt.tm_min, ttt.tm_sec, __FUNCTION__ , __LINE__, ##__VA_ARGS__);}}while(0)

#endif

#endif
