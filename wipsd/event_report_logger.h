#ifndef EVENT_REPORT_LOGGER
#define EVENT_REPORT_LOGGER

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include "ring.h"

struct event_report_logger_config {
	int ringsize;
	int nodesize;
	int gate;
	int (* logfunc) (struct ring_control*, int lognum); 
};   // logfunc 需要互斥访问, setlogfunc_初始化后仅使用一次

struct event_report_logger_control {
	struct ring_control* logbuffer;
	struct event_report_logger_config logconfig;
	sem_t logsem_wait; // 
	sem_t logsem_do; // 
	pthread_t logthread;
	sig_atomic_t event_to_log_num;
	sig_atomic_t thread_ctl;
	sig_atomic_t flush_nodenum;
};

extern struct event_report_logger_control* init_event_report_logger( int buffersize, int nodesize, int loggate );
extern int setlogfunc_event_report_logger(struct event_report_logger_control* logctl, int (* logfunc) (struct ring_control*, int));
extern int tellto_event_report_logger(struct event_report_logger_control* logctl, void* event);
extern int isok_event_report_logger(struct event_report_logger_control* logctl);
extern int flush_event_report_logger(struct event_report_logger_control* logctl);
extern void delete_event_report_logger(struct event_report_logger_control* logctl);

#endif
