#include <zebra.h>
#include "vsos_syslib.h"
#include "zthread_support.h"
#include "if_support.h"
#include "fs_support.h"
#include "io_support.h"
#include "getopt.h"
#include "daemon.h"
#include "mac.h"
#include "zclient.h"
#include "vty.h"
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
//#include <sqlite3.h>
#include "hash.h"
#include "ieee80211.h"

#include "debug.h"
#include "event_report_logger.h"
#include "ring.h"

//#define DEBUG_UNIT
#if 1

//fndef DEBUG_UNIT
//externs
#include "wipsd_wnode.h"
#include "sys/lfd_log.h"

#include "wipsd.h"

static struct daemon wips_dm[2]={
			{.name = "WIPSÊÂ¼þ", 
			 .keyword = "WEVENT", 
			 .fac = WEVENT
			 },{
			 .name = "WIPSÏµÍ³", 
			 .keyword = "WSYSTEM", 
			 .fac = WSYSTEM}};

extern wevent_struct* wevent_list;
extern int wips_event_syslog_out;


extern char * prepare_log_data(struct w_node *ap_val, int event, int pri);
//note: REPORT_VALUE_TYPE struct w_node ( REQ: .ssid-s, .channel-d, .block-d, node_type-d )
//note: wevent_struct* wevent_list ( REQ: .name-s, .pri-s, .id-d, .is_grp-d, .grp_id-d )
//note: WIPS_LOG_DB -s
//note: WIPS_EID_MAX -d
//note: WIPS_EID_ACTION_GRP -d
//note: wevent_pri* eve_pri_table (REQ: .pri-d )
//note: struct daemon* DM (REQ: .fac-d)
//note: EVENT 0
//externs end
#else
//define extern STUFF

struct wevent_struct {
	char name[30];
	char pri[20];
	int id;
	int is_grp;
	int grp_id;
}  wevent_list[10]={{.name={"name"},.pri={"pri"}}}
struct w_node {
	char ssid[30];
	char mac[20];
	char bssid[6];
	int channel;
	int block;
	int node_type;
};
struct wevent_pri {
	char name[20];
	int pri;
} eve_pri_table[10]={{.name={"name"}}};
struct daemon {
	int fac;
} mem_log[10];

static char * prepare_log_data(struct w_node *ap_val, int event, int pri) {
	char* logstr = (char*)malloc(100)
	sprintf(logstr, "DEBUG: prepare_log_data(), ssid:%s, event:%2d, pri:%2d", ap_val==NULL?"NULL":ap_val->ssid, event, pri);
	return logstr;
}
#define WIPS_EID_MAX 10
#define WIPS_EID_ACTION_GRP 8
#endif

#include "event_mem_log.h"
//#include "wipsd_wpolicy.h"

#define GEN_TIMESTR_BY_TIMEVAL(stimeval, timestrname) \
  char timestrname[100]; \
  {  struct tm* localtm=vsos_localtime(&(stimeval.tv_sec));	     \
     sprintf(timestrname, "%d-%02d-%02d %02d:%02d:%02d.%06ld",  \
     localtm->tm_year+1900, localtm->tm_mon+1, localtm->tm_mday, \
     localtm->tm_hour, localtm->tm_min, localtm->tm_sec, stimeval.tv_usec);}

pthread_mutex_t event_memlog_mutex=PTHREAD_MUTEX_INITIALIZER;
struct memlog event_memlog;

int event_memlog_push(struct event_memlog_pkt* pkt);


struct event_report_logger_control* __mem_logctl__=NULL;
sig_atomic_t __memlog_timeout_countdown__=EVENT_MEM_TIMEOUT_SECONDS;

static int report_ap_event_acext(struct event_memlog_pkt* pkt)//acext means access extern variables
{
	REPORT_VALUE_TYPE* wnode=&(pkt->val);
	int event = pkt->type;
//	int logmode = pkt->logmode;
	int retcode=0;//bit0: memlog, bit1:syslog
	if( (pkt->logDone & 0x2) == 0x2) goto ap_sys_log_success;

	int log_pri = eve_pri_table[event -1].pri;
	char* pbuf = prepare_log_data(wnode, event, log_pri);
	if(pbuf==NULL) goto ap_sys_log_fail;
	log_pri = wips_dm[EVENT].fac  * 8  + log_pri;
	//syslog(log_pri, "%s", pbuf);
	vsos_syslog(MODULE_WIPS, LOG_INFO,"%s\n", pbuf);		
	XFREE(MTYPE_WIPS_DEBUG_LOG,pbuf);
ap_sys_log_success:
	pkt->logDone |= 2;
	retcode |= 2;
	goto ap_sys_log_exit;
	ap_sys_log_fail:
		retcode &= ~2;
ap_sys_log_exit:
	return retcode;
} 
  
static int report_sta_event_acext(struct event_memlog_pkt* pkt)//acext means access extern variables
{
	REPORT_VALUE_TYPE* wnode=&(pkt->val);
	int event = pkt->type;
	int logmode = pkt->logmode;
	int retcode=0;//bit0: memlog, bit1:syslog

	if ( logmode==0 || logmode== 2 ){ //log in sys
       	if( (pkt->logDone & 0x2) == 0x2) goto sta_sys_log_success;
		int log_pri = eve_pri_table[event -1].pri;
		char* pbuf =prepare_log_data(wnode, event, log_pri);
		if(pbuf==NULL) goto sta_sys_log_fail;
		log_pri = wips_dm[EVENT].fac  * 8  + log_pri;
		//syslog(log_pri, "%s", pbuf);
		vsos_syslog(MODULE_WIPS, LOG_INFO,"%s\n", pbuf);
	XFREE(MTYPE_WIPS_DEBUG_LOG,pbuf);
	sta_sys_log_success:
		pkt->logDone |= 2;
		retcode |= 2;
		goto sta_sys_log_exit;
	sta_sys_log_fail:
		retcode &= ~2;
	}
sta_sys_log_exit:
	return retcode;
}

static int report_all_event_acext(struct event_memlog_pkt* pkt)//acext means access extern variables
{
	REPORT_VALUE_TYPE *node=&(pkt->val);
	
	if((node->node_type & 0x01)==0x01){
		report_ap_event_acext(pkt);
	}
	if(node->node_type & 0x06){
		report_sta_event_acext(pkt);
	}

	return 0;
}

#if 0
static int report_all_event_acext(struct event_memlog_pkt* pkt)//acext means access extern variables
{
	REPORT_VALUE_TYPE *node=&(pkt->val);
	int retvalue=0;
	if((node->node_type & 0x01)==0x01){
		if(0)
		retvalue += report_ap_event_acext(pkt);
	}
	if(node->node_type & 0x06){
		if(0)
		retvalue += report_sta_event_acext(pkt);
	}

	return retvalue;
}
#endif

#if 0
int event_memlog_push(struct event_memlog_pkt* pkt)
{
	int event = 0;
	struct memlog_data_t *memlog_data = NULL;
	REPORT_VALUE_TYPE* node=&(pkt->val);
	
	pthread_mutex_lock(&event_memlog_mutex);
		
	GEN_TIMESTR_BY_TIMEVAL(pkt->when_event_happen, detect_time);
	memlog_data = &event_memlog.log[event_memlog.cur];

	memlog_data->log_num = 0;
	snprintf((void *)memlog_data->name, sizeof(memlog_data->name), "%s", node->name);
	snprintf((void *)memlog_data->ssid,sizeof(memlog_data->ssid), "%s", node->ssid);
	snprintf((void *)memlog_data->up_time,sizeof(memlog_data->up_time), "%s", detect_time);
	snprintf((void *)memlog_data->bssid,sizeof(memlog_data->bssid), MACSTR, MAC2STR(node->bssid));
	snprintf((void *)memlog_data->channel,sizeof(memlog_data->channel), "%d", node->channel);
	snprintf((void *)memlog_data->mac,sizeof(memlog_data->mac), MACSTR, MAC2STR(node->mac));
	snprintf((void *)memlog_data->permit,sizeof(memlog_data->permit), "%d", node->block);

	event = pkt->type;
	if(event < WIPS_EID_MAX){
		snprintf((void *)memlog_data->pri,sizeof(memlog_data->pri), "%s", wevent_list[event -1].pri);
		strncpy((void *)memlog_data->alert, wevent_list[event -1].name, sizeof(memlog_data->alert));
	}else if(event > WIPS_EID_MAX){
		snprintf((void *)memlog_data->pri,sizeof(memlog_data->pri), "%s", "¿¿");
		strncpy((void *)memlog_data->alert, eve_pri_table[event-1].name, sizeof(memlog_data->alert));
	}
	
	if (event_memlog.cur == event_memlog.end){
		event_memlog.start = (event_memlog.start + 1)%event_memlog.num;
		event_memlog.end = (event_memlog.end + 1)%event_memlog.num;
	}
	
	event_memlog.cur = (event_memlog.cur + 1)%event_memlog.num;
	
	pthread_mutex_unlock(&event_memlog_mutex);

	return 0;
}
#else
int event_memlog_push(struct event_memlog_pkt* pkt)
{
	int event = 0;
	struct memlog_data_t *memlog_data = NULL;
	REPORT_VALUE_TYPE* node=&(pkt->val);
	
	//pthread_mutex_lock(&event_memlog_mutex);
		
	GEN_TIMESTR_BY_TIMEVAL(pkt->when_event_happen, detect_time);
	memlog_data = &event_memlog.log[event_memlog.cur];

	memlog_data->log_num = 0;
	snprintf((void *)memlog_data->name, sizeof(memlog_data->name), "%s", node->name);
	snprintf((void *)memlog_data->ssid,sizeof(memlog_data->ssid), "%s", node->ssid);
	snprintf((void *)memlog_data->up_time,sizeof(memlog_data->up_time), "%s", detect_time);
	snprintf((void *)memlog_data->bssid,sizeof(memlog_data->bssid), MACSTR, MAC2STR(node->bssid));
	snprintf((void *)memlog_data->channel,sizeof(memlog_data->channel), "%d", node->channel);
	snprintf((void *)memlog_data->mac,sizeof(memlog_data->mac), MACSTR, MAC2STR(node->mac));
	snprintf((void *)memlog_data->permit,sizeof(memlog_data->permit), "%d", node->block);

	event = pkt->type;
	if(event < WIPS_EID_MAX){
		snprintf((void *)memlog_data->pri,sizeof(memlog_data->pri), "%s", wevent_list[event -1].pri);
		strncpy((void *)memlog_data->alert, wevent_list[event -1].name, sizeof(memlog_data->alert));
	}else if(event > WIPS_EID_MAX){
		snprintf((void *)memlog_data->pri,sizeof(memlog_data->pri), "%s", "��ʾ");
		strncpy((void *)memlog_data->alert, eve_pri_table[event-1].name, sizeof(memlog_data->alert));
	}
	
	if (event_memlog.cur == event_memlog.end){
		event_memlog.start = (event_memlog.start + 1)%event_memlog.num;
		event_memlog.end = (event_memlog.end + 1)%event_memlog.num;
	}
	
	event_memlog.cur = (event_memlog.cur + 1)%event_memlog.num;
	if(wips_event_syslog_out)
	{ //add by dingkang
		char str[1024];
		memset(str,0,1024);

		sprintf(str, "INFO_TYPE=\"EVENT_INFO\" {ID:%d, attack:\"%s\"attack_id:\"%d\", risk:\"%s\", mac:\"%s\", bssid:\"%s\", "
		       "ssid:\"%s\", name:\"%s\", channel:\"%s\","
		       "time:\"%s\"}",           
			memlog_data->log_num,memlog_data->alert,event-1, wevent_list[event -1].pri,  memlog_data->mac, memlog_data->bssid, 
			memlog_data->ssid, memlog_data->name, memlog_data->channel, memlog_data->up_time);
		vsos_syslog_2(MODULE_ACD, 0,"%s\n",str);

	}
	//pthread_mutex_unlock(&event_memlog_mutex);

	return 0;
}
#endif

#if 0
static int event_mem_logfunc(struct ring_control* buffer, int lognum)
{
  // 1.è¿œç¨‹è®°å½•
  // 2.æŒ‰æŒ‡å®šGAPç§»åŠ¨çŽ¯
	struct event_memlog_pkt* pkt;
	//static int ringfd=-1;
	int savecount=0;
	int i;

	for(i=0; i<lognum; i++){
		if(  dequeue_ring(buffer, (void**)&pkt) != 0 ){
			event_memlog_push(pkt);
			report_all_event_acext(pkt);
			savecount++;
		}else{ // dequeue error
			break;
		}
	}

#if 0	
	for(i=0; i<lognum; i++){
	  ringfd = traverse_ring(buffer, ringfd, (void*)&pkt);
		if( pkt!=NULL ){
		report_all_event_acext(pkt);
		savecount++;
		}
	}
	
	sig_atomic_t ringlen=getlength_ring(buffer);
	for(i=EVENT_MEM_LOGGER_BUFFERSIZE; i<ringlen; i++){
		dequeue_ring(buffer, NULL);
		
		//syslog
		//report_all_event_acext(pkt);
	}
#endif	
	//clog_exit:
	if(savecount>0) 
		__memlog_timeout_countdown__ = EVENT_MEM_TIMEOUT_SECONDS;
	return savecount;

}

int init_event_memlog(void)
{
	__mem_logctl__ = init_event_report_logger( EVENT_MEM_LOGGER_BUFFERSIZE+EVENT_MEM_LOGGER_GAP, EVENT_MEM_LOGGER_NODESIZE, EVENT_MEM_LOGGER_GATE );
	if(__mem_logctl__==NULL)
		return 0;

	memset(&event_memlog, 0 , sizeof(event_memlog));
	event_memlog.num = sizeof(event_memlog.log) / sizeof(struct memlog_data_t);
	event_memlog.start = 0;
	event_memlog.end = event_memlog.num - 1;
	event_memlog.cur = event_memlog.start;
	setlogfunc_event_report_logger(__mem_logctl__, event_mem_logfunc);
	return 1;
}
#else
int init_event_memlog(void)
{
	memset(&event_memlog, 0 , sizeof(event_memlog));
	event_memlog.num = sizeof(event_memlog.log) / sizeof(struct memlog_data_t);
	event_memlog.start = 0;
	event_memlog.end = event_memlog.num - 1;
	event_memlog.cur = event_memlog.start;
	return 1;
}
#endif
#if 0
void delete_event_memlog(void)
{
	if(__mem_logctl__!=NULL){
		delete_event_report_logger(__mem_logctl__);
		__mem_logctl__ = NULL;
	}
}
#endif
int flush_event_memlog(void)
{
	return flush_event_report_logger(__mem_logctl__);
}

int tryflush_event_memlog(void)
{
	if(--__memlog_timeout_countdown__<=0 && __mem_logctl__!=NULL){
		__memlog_timeout_countdown__ = EVENT_MEM_TIMEOUT_SECONDS;
		return flush_event_memlog();
	}
	return 0;
}

int log_event_memlog(REPORT_VALUE_TYPE* ap_val, int event, int logmode)
{
	struct event_memlog_pkt __event_pkt__;
	__event_pkt__.val = *ap_val;
	__event_pkt__.type = event;
	__event_pkt__.logmode = logmode; //0:all, 1:sql, 2:sys
	__event_pkt__.logDone = 0;
	gettimeofday(&__event_pkt__.when_event_happen, NULL);


#if 0
	int retcode=tellto_event_report_logger(__mem_logctl__, &__event_pkt__);
#else
    if ((event == WIPS_EID_STA_BLOCK_START) || (event == WIPS_EID_AP_BLOCK_START))
    {
		WIPSD_DEBUG("%s-%d:event:%d, node type=%x mac=%02x:%02x:%02x:%02x:%02x:%02x"
          " bssid=%02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__, 
			event, ap_val->node_type, ap_val->mac[0],ap_val->mac[1],ap_val->mac[2],ap_val->mac[3],ap_val->mac[4],ap_val->mac[5],
			ap_val->bssid[0],ap_val->bssid[1],ap_val->bssid[2],ap_val->bssid[3],ap_val->bssid[4],ap_val->bssid[5]);
    }
	event_memlog_push(&__event_pkt__);
	report_all_event_acext(&__event_pkt__);
#endif

	return 0;
}

int snapshot_event_memlog(void* membigenough, int nodenum)
{
	sig_atomic_t head;
	sig_atomic_t tail;
	if( snapshot_ring(__mem_logctl__->logbuffer, &head, &tail)==1 ){
		sig_atomic_t exphead;
		tail += tail<head ? __mem_logctl__->logbuffer->capacity : 0;
		exphead = tail - nodenum +1;
		exphead = exphead > head ? exphead : head;
		tail %= __mem_logctl__->logbuffer->capacity;
		exphead %= __mem_logctl__->logbuffer->capacity;
		return getnodes_ring(__mem_logctl__->logbuffer, exphead, tail, membigenough);
	}
	return 0;
}

#ifdef DEBUG_UNIT
#if 0
void timer()
{ tryflush_event_memlog(); 
  DRLT(1, 0, "TIME LEVEL: %d", __memlog_timeout_countdown__);}
int main(int argn, char* argv[])
{
	void* mem = malloc(sizeof(struct event_memlog_pkt)*EVENT_MEM_LOGGER_BUFFERSIZE)
	init_event_memlog();
	REPORT_VALUE_TYPE x={ .ssid={"00:23:45:67:89:ab"}, .node_type=1 };
	signal(SIGALRM, timer);
	struct itimerval timerval={.it_interval.tv_sec=0, .it_interval.tv_usec=500000, .it_value.tv_sec=0, .it_value.tv_usec=500000};
	setitimer(ITIMER_REAL, &timerval, NULL);
	int i,j;
	for(;;){
		log_event_memlog(&x, 1, 1);
		for(i=0;i<1000000;i++);
		sleep(1);
		j=snapshot_event_memlog(mem, EVENT_MEM_LOGGER_BUFFERSIZE);
		for(i=0;i<j;i++)
			WIPSD_DEBUG("%d", ((struct event_memlog_pkt*)mem+i)->val.node_type);
		WIPSD_DEBUG("\n");
	}
	sleep(1);
	delete_event_memlog();
	wipsd_free(mem);
	return 0;
}
#endif
#endif

