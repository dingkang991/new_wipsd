#ifndef DEBUG_H
#define DEBUG_H


/*#define DEBUG*/
#define PK_TO_DEBUG

//common
#define DL_ERR 0
#define DL_MEM 1 //malloc free 
#define DL_DB 2 //database

//special
#ifdef PK_TO_DEBUG
#define DL_EVENTLOG_PRE 9
#define DL_EVENTLOG_LOG 10
#define DL_EVENTLOG_POST 11
#else 
#define DL_EVENTLOG_PRE -1
#define DL_EVENTLOG_LOG -1
#define DL_EVENTLOG_POST -1
#endif

extern unsigned char wipsd_debug;
#define WIPSD_DEBUG(X...) \
	do { \
		if (wipsd_debug) { \
			XPRINT(X); \
		} \
	} while (0)

#ifndef DEBUG

#define DR(fd, level, args...)
#define DRL(fd, level, args...)
#define DRT(fd, level, args...)
#define DRLT(fd, level, args...)
#define DEBUG_HOOK(mode)

#else

#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


#define	DEBUG_LEVEL_NUM				(sizeof(int)*8)
#define	DEBUG_LEVEL_ON_ALL			(~(unsigned int)0)
#define	DEBUG_LEVEL_OFF_ALL			0
#define	DEBUG_LEVEL_ON_INIT			((1<<0)|(1<<31)/*|(1<<10)|(1<<11)*/)
#define	DEBUG_LEVEL_ON				(debug_shm==NULL?DEBUG_LEVEL_ON_INIT:debug_shm->level_onflags)

#define LEVEL_LOG(i) (1+i)
#define LEVEL_BUG_ALWAYS(i) (25+i)
#define LEVEL_BUG_MAYBE(i) (9+i)

#define __LOCAL_DEBUG_FILE__			(debug_shm!=NULL&&debug_shm->logfd!=-1?debug_shm->logfd:-1)
#define DEBUG_LOG_TO_FILE(args...) {\
	char loginfo[512];\
	int len=sprintf(loginfo, ""args);	\
	len=write(__LOCAL_DEBUG_FILE__, loginfo, len);\
}

#define DEBUG_LEVEL_TAGSTR "V"
#define DEBUG_TIME_TAGSTR "T"
#define DEBUG_TRACE_TAGSTR "L"

#define DEBUG_LEVEL_FORMATSTR "\n<"DEBUG_LEVEL_TAGSTR" %d>"
#define DEBUG_TIME_FORMATSTR " <"DEBUG_TIME_TAGSTR" %s>, "
#define DEBUG_TRACE_FORMATSTR " <"DEBUG_TRACE_TAGSTR" %s(%d): %s>, ",__FILE__,__LINE__,__FUNCTION__

#define DEBUG_GET_TIMESTR_NOW(timestrname) \
	char timestrname[100]; \
	struct timeval tval; \
	gettimeofday(&tval, NULL); \
	struct tm* localtm=localtime(&(tval.tv_sec));	     \
	sprintf(timestrname, "%d-%02d-%02d %02d:%02d:%02d.%06ld",  \
	localtm->tm_year+1900, localtm->tm_mon+1, localtm->tm_mday, \
	localtm->tm_hour, localtm->tm_min, localtm->tm_sec, tval.tv_usec);
	
#define DR(level, fd,  args...) {\
	if(  level<DEBUG_LEVEL_NUM && (((unsigned int)1<<level)&(DEBUG_LEVEL_ON)) ){ \
		if(fd%2!=0){\
			WIPSD_DEBUG(DEBUG_LEVEL_FORMATSTR, level);\
			WIPSD_DEBUG(""args);\
		}\
		if( (fd&2)!=0 && __LOCAL_DEBUG_FILE__!=-1 ){\
		        DEBUG_LOG_TO_FILE(DEBUG_LEVEL_FORMATSTR, level);\
		        DEBUG_LOG_TO_FILE(args);\
		}\
	}\
}

#define DRL(level, fd,  args...) {\
	if(  level<DEBUG_LEVEL_NUM && (((unsigned int)1<<level)&(DEBUG_LEVEL_ON)) ){ \
		if(fd%2!=0){\
			WIPSD_DEBUG(DEBUG_LEVEL_FORMATSTR, level);\
			WIPSD_DEBUG(DEBUG_TRACE_FORMATSTR);\
			WIPSD_DEBUG(""args);		      \
		}\
		if( (fd&2)!=0 && __LOCAL_DEBUG_FILE__!=-1 ){	\
			DEBUG_LOG_TO_FILE( DEBUG_LEVEL_FORMATSTR, level);\
			DEBUG_LOG_TO_FILE( DEBUG_TRACE_FORMATSTR);\
			DEBUG_LOG_TO_FILE( args);\
		}\
	}\
}

#define DRT(level, fd, args...) {\
	if(  level<DEBUG_LEVEL_NUM && (((unsigned int)1<<level)&(DEBUG_LEVEL_ON)) ){ \
		DEBUG_GET_TIMESTR_NOW(timestr);\
		if(fd%2!=0){\
			WIPSD_DEBUG(DEBUG_LEVEL_FORMATSTR, level);\
			WIPSD_DEBUG(DEBUG_TIME_FORMATSTR, timestr);\
			WIPSD_DEBUG(""args);\
		}\
		if( (fd&2)!=0 && __LOCAL_DEBUG_FILE__!=-1 ){	\
			DEBUG_LOG_TO_FILE( DEBUG_LEVEL_FORMATSTR, level);\
	      		DEBUG_LOG_TO_FILE( DEBUG_TIME_FORMATSTR, timestr);  \
			DEBUG_LOG_TO_FILE( args);\
		}\
	}\
}

#define DRLT(level, fd, args...) {\
	if(  level<DEBUG_LEVEL_NUM && (((unsigned int)1<<level)&(DEBUG_LEVEL_ON)) ){ \
		DEBUG_GET_TIMESTR_NOW(timestr);\
		if(fd%2!=0){\
			WIPSD_DEBUG(DEBUG_LEVEL_FORMATSTR, level);\
			WIPSD_DEBUG(DEBUG_TRACE_FORMATSTR);\
			WIPSD_DEBUG(DEBUG_TIME_FORMATSTR, timestr);\
			WIPSD_DEBUG(""args);\
		}\
		if( (fd&2)!=0 && __LOCAL_DEBUG_FILE__!=-1 ){	\
			DEBUG_LOG_TO_FILE( DEBUG_LEVEL_FORMATSTR, level);\
			DEBUG_LOG_TO_FILE( DEBUG_TRACE_FORMATSTR);\
			DEBUG_LOG_TO_FILE( DEBUG_TIME_FORMATSTR, timestr);\
			DEBUG_LOG_TO_FILE( args);\
		}\
	}\
}

#include <signal.h>
#include <execinfo.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

struct debug_share {
	int sizeofme;
	unsigned int level_onflags;
	int key;

	int logfd;
	char logfn[50];
	int logfc;
	int loggate;
};
extern struct debug_share* debug_shm;

#define DEBUG_HOOK(debug_log_mode)\
static void __dump(int signo)\
{\
	void *array[10];\
	size_t size;\
	char **strings;\
	size_t i;\
	size = backtrace (array, 10);\
	strings = backtrace_symbols (array, size);\
	WIPSD_DEBUG ("Obtained %zd stack frames.\n", size);\
	for (i = 0; i < size; i++)\
		WIPSD_DEBUG ("%s\n", strings[i]);\
	free (strings);\
	exit(0);\
}\
 __attribute__ ((constructor)) void __BeforeMain() \
{\
	signal(SIGSEGV, &__dump);\
	FILE* keyfile;\
	char kfname[150];\
        int debug_shm_id = -1;\
	sprintf(kfname, "/tmp/%s.key", __FILE__);\
	if((keyfile=fopen(kfname, "r"))!=NULL){\
	        fscanf(keyfile, "%d", &debug_shm_id);\
	        fclose(keyfile);\
		debug_shm = shmat(debug_shm_id, 0, 0);\
		debug_shm_id = debug_shm==(void*)-1?-1:debug_shm_id;\
	}\
        if(debug_shm_id==-1 || debug_shm->sizeofme!=sizeof(*debug_shm)){ \
	        debug_shm_id = shmget(IPC_PRIVATE, sizeof(*debug_shm), IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IROTH);\
	        debug_shm = shmat(debug_shm_id, 0, 0);\
	        if(debug_shm==(void*)-1) {\
			WIPSD_DEBUG("/nerror: Debug sharemem create fail!");\
			debug_shm = NULL;\
			return;\
		}\
		debug_shm->sizeofme 		= 	sizeof(*debug_shm);\
		debug_shm->level_onflags 	= 	DEBUG_LEVEL_ON_INIT;\
		debug_shm->loggate		=	5;\
		debug_shm->logfc		=	0;\
		debug_shm->logfd		=	-1;\
		debug_shm->key			=	debug_shm_id;\
		char fname[150];\
		sprintf(fname, "/tmp/%s.key", __FILE__);\
		FILE* keylogfile = fopen(fname, "w+");\
		if(keylogfile==NULL){\
			WIPSD_DEBUG("/nerror: Debug sharemem key file create fail!");\
		}\
		fprintf(keylogfile, "%d\n", debug_shm_id);\
		fclose(keylogfile);\
	}\
	sprintf(debug_shm->logfn, "/tmp/%s.dbg", __FILE__);\
	if( (debug_shm->logfd = open(debug_shm->logfn,  O_WRONLY | O_APPEND | O_CREAT | (debug_log_mode?0:O_TRUNC), 0777))==-1 ){ \
		WIPSD_DEBUG("/nerror: Debug log file \"%s\"open/create fail!", debug_shm->logfn);\
		return;\
		}\
}\
\
__attribute__ ((destructor)) void __AfterMain()\
{\
	if(debug_shm!=NULL && debug_shm->logfd!=-1){\
		close(debug_shm->logfd);\
		debug_shm->logfd = -1;\
 	}\
	if(debug_shm!=NULL){\
		shmdt(debug_shm);\
	}\
 }

#endif

#endif
