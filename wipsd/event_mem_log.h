#ifndef EVENT_MEM_LOG
#define EVENT_MEM_LOG

#define EVENT_MEM_LOGGER_GAP 10
#define EVENT_MEM_MAX_NUM	1200
#define EVENT_MEM_LOGGER_GATE 1
#define EVENT_MEM_TIMEOUT_SECONDS 7 // 超时时间(秒)
#define REPORT_VALUE_TYPE struct w_node
#define EVENT_MEM_LOGGER_BUFFERSIZE 10
//#define REPORT_VALUE_TYPE double
struct event_memlog_pkt {
	REPORT_VALUE_TYPE val;//wnode
	int type;//event type
	int logmode;
	struct timeval when_event_happen;
	int logDone;//bit 0:memlog done, bit 1:syslog done
};
#define EVENT_MEM_LOGGER_NODESIZE sizeof(struct event_memlog_pkt)

#if 1
struct memlog_data_t{
	u32 log_num;
	u8 bssid[24];
	u8 mac[24];
	u8 channel[4];
	u8 alert[128];		//wevent_list[event-1].name event = pkt->type
	u8 permit[4];
	u8 pri[8];
	u8 up_time[24];
	u8 name[64];
	u8 ssid[64];
};

struct memlog{
	int num;
	int start;
	int end;
	int cur;
	struct memlog_data_t log[EVENT_MEM_MAX_NUM];
};
#endif
extern int init_event_memlog(void);
extern void delete_event_memlog(void);
extern int log_event_memlog(REPORT_VALUE_TYPE* ap_val, int event, int logmode);
extern int snapshot_event_memlog(void* membigenough, int nodenum);

#endif
