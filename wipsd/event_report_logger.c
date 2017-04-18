#include <zebra.h>
#include "zthread_support.h"
#include "if_support.h"
#include "fs_support.h"
#include "io_support.h"
#include "getopt.h"
#include "daemon.h"
#include "mac.h"
#include "zclient.h"
#include "vty.h"
#include "../vtysh/vtysh.h"
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include <linux/in.h>
#include "obstack.h"
#include "hash.h"
#include "ieee80211.h"
#include "sqlite3.h"

#include "event_report_logger.h"
#include "wipsd_wnode.h"
#include "debug.h"

//static int default_logfunc(struct ring_control* buffer, int lognum);
//static void* logthread(void*);
#if 0
struct event_report_logger_control* init_event_report_logger(int buffersize, int nodesize, int loggate)
{
	void* memclean[3];
	int mem_c=0;
#define PUSH_ALLOC(address) (memclean[mem_c++]=(address))
#define POP_ALLOC() (memclean[mem_c--])
#define WIPSD_XMALLOC(var, size) { \
	if(PUSH_ALLOC(var=malloc(size))==NULL) \
		goto exit_mem_fail; \
}
	
	struct event_report_logger_control* logctl;
	
 	WIPSD_XMALLOC(logctl, sizeof(*logctl));
	if((logctl->logbuffer = new_ring(buffersize, nodesize))==NULL) goto exit_mem_fail;
	if(sem_init(&(logctl->logsem_wait), 0, 0)!=0) goto exit_ensem_fail;
	if(sem_init(&(logctl->logsem_do), 0, 0)!=0) goto exit_desem_fail;
	logctl->logconfig.ringsize = buffersize;
	logctl->logconfig.nodesize = nodesize;
	logctl->logconfig.gate = loggate;
	logctl->logconfig.logfunc = NULL;
	logctl->event_to_log_num = 0;
	logctl->flush_nodenum = 0;
	logctl->thread_ctl = 1;
	setlogfunc_event_report_logger(logctl, default_logfunc);
{	int ret;
	pthread_attr_t attr;
	ret = pthread_attr_init(&attr);
	if (ret != 0)
		goto exit_thread_fail;
	ret = pthread_attr_setstacksize(&attr, 8388608);//131072);
	if(ret != 0)
		goto exit_thread_fail;
	if(pthread_create(&(logctl->logthread), &attr,  logthread, logctl)!=0) goto exit_thread_fail;
}	return logctl;
exit_thread_fail:// thread 创建失败
	sem_destroy(&(logctl->logsem_do));
exit_desem_fail:// desem 创建失败
	sem_destroy(&(logctl->logsem_wait));
exit_ensem_fail:// ensem 创建失败
	delete_ring(logctl->logbuffer);
exit_mem_fail: // 内存分配失败
	while(mem_c>=0) free(POP_ALLOC());
	return NULL;
}
#endif
int setlogfunc_event_report_logger(struct event_report_logger_control* logctl, int (* logfunc) (struct ring_control*, int))
{
	return logctl==NULL ? 0 : ((logctl->logconfig.logfunc=logfunc)!=NULL);
}

static int trytellto_event_report_logger(struct event_report_logger_control* logctl, void* event)
{
	if(is_ring_full(logctl->logbuffer)==0){ //success
		if(enqueue_ring(logctl->logbuffer, event)==0) { //fail
		goto tellto_exit_fail;
		}
		sem_post(&logctl->logsem_wait);  // 记录组增加
		sem_trywait(&logctl->logsem_do); // 触发线程切换 
		return 1;
	}
	WIPSD_DEBUG("ERROR: Ring Full!\n");
tellto_exit_fail:
	return 0;
}

int tellto_event_report_logger(struct event_report_logger_control* logctl, void* event)
{
	return trytellto_event_report_logger(logctl, event);
}

int isok_event_report_logger(struct event_report_logger_control* logctl)
{
	return logctl==NULL?0:isflowover_ring(logctl->logbuffer);
}
#if 0
void delete_event_report_logger(struct event_report_logger_control* logctl)
{
	if(logctl!=NULL){
		logctl->thread_ctl = 0;
		sem_post(&(logctl->logsem_wait));
		sem_trywait(&logctl->logsem_do); // 触发线程切换 
		pthread_join(logctl->logthread, NULL);
		sem_destroy(&logctl->logsem_do);
		sem_destroy(&logctl->logsem_wait);
		delete_ring(logctl->logbuffer);
		wipsd_free(logctl);
	}
}
#endif
int flush_event_report_logger(struct event_report_logger_control* logctl)
{
	logctl->flush_nodenum = logctl->logbuffer->nodenum;
	if(logctl->flush_nodenum==0)
	  return 0;
	sem_post(&(logctl->logsem_wait));
	sem_trywait(&logctl->logsem_do); // 触发线程切换 
	return 1;
}
#if 0 
static int default_logfunc(struct ring_control* buffer, int lognum)
{
	//
	// REQ: 返回正确入库的节点数
	//
	int i;
	for(i=0;i<lognum;i++){
		if(dequeue_ring(buffer, NULL)==0) break;
	}
	return i;
}

static void* logthread(void* plog)
{
	struct event_report_logger_control* logctl = (struct event_report_logger_control*) plog;
	while(logctl->thread_ctl){
		sem_wait(&logctl->logsem_wait);
		++logctl->event_to_log_num;
		if( logctl->flush_nodenum>0 ){
		   --logctl->event_to_log_num;
#ifdef MEMLOG
		   logctl->logconfig.logfunc(logctl->logbuffer, logctl->event_to_log_num);
		   logctl->flush_nodenum = 0;
#else
		   int reallognum=logctl->logconfig.logfunc(logctl->logbuffer, logctl->flush_nodenum);
		   logctl->flush_nodenum -= reallognum;
		   logctl->event_to_log_num -= reallognum;
		   if( logctl->flush_nodenum > 0){
		     sem_post(&logctl->logsem_wait);
		   }else if(logctl->flush_nodenum < 0){
		     logctl->flush_nodenum = 0;
		   }
#endif
		}else if( logctl->event_to_log_num >= logctl->logconfig.gate ){
			logctl->event_to_log_num -= logctl->logconfig.logfunc(logctl->logbuffer, logctl->event_to_log_num);
			logctl->flush_nodenum = 0;
		}
	}
	return NULL;
}

/*
 * Example.
 */
 #endif
#if 0
static int mylogfunc(struct ring_control* buffer, int lognum)
{
	int i=0;
	float* x;
	for(i=0;i<lognum;i++){
		dequeue_ring(buffer, (void**)&x);
		printf("%f\t", *x);
	}
	printf("\n");
	return i;
}

int main(int argn, char* argv[])
{
	struct event_report_logger_control* logctl;
	logctl = init_event_report_logger( 80, sizeof(float), 5);
	setlogfunc_event_report_logger(logctl, mylogfunc);
	float x=1.5;
	int i=0;
	for(i=0;i<50;i++){
		tellto_event_report_logger(logctl, &x);
		x *= 1.5;    
	}
	sleep(1);
	delete_event_report_logger(logctl);
	return 0;
}
#endif
