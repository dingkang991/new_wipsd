#ifndef EVENT_SQL_LOG
#define EVENT_SQL_LOG

#define EVENT_SQL_LOGGER_BUFFERSIZE 	1000
#define EVENT_SQL_LOGGER_GATE 			20
#define EVENT_SQL_MAX_NUM				1200
#define EVENT_SQL_TIMEOUT_SECONDS 	3 // 超时时间(秒)
#define REPORT_VALUE_TYPE struct w_node
//#define REPORT_VALUE_TYPE double

extern int init_event_sqllog(const char* dbfilename);
extern void delete_event_sqllog(void);
extern int flush_event_sqllog(void);
extern int tryflush_event_sqllog(void);
extern int log_event_sqllog(REPORT_VALUE_TYPE* ap_val, int event, int logmode);

#endif
