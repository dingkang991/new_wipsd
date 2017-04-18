#if 0
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <sqlite3.h>

#include "message.h"
#include "debug.h"
#include "event_report_logger.h"


#if 1
//#ifndef DEBUG_UNIT
//externs
#include <time.h>
#include <syslog.h>
#include "wipsd_wnode.h"
#include "sys/lfd_log.h"
#include "wipsd_sql.h"
#include "wipsd.h"

static struct daemon wips_dm[2]={
			{.name = "WIPS事件", 
			 .keyword = "WEVENT", 
			 .fac = WEVENT
			 },{
			 .name = "WIPS系统", 
			 .keyword = "WSYSTEM", 
			 .fac = WSYSTEM}};


extern wevent_struct* wevent_list;
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
}  wevent_list[10]={{.name={"name"},.pri={"pri"}}};
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
} DM[10];

static char * prepare_log_data(struct w_node *ap_val, int event, int pri) {
	char* logstr = (char*)malloc(100)
	sprintf(logstr, "DEBUG: prepare_log_data(), ssid:%s, event:%2d, pri:%2d", ap_val==NULL?"NULL":ap_val->ssid, event, pri);
	return logstr;
}
#define WIPS_LOG_DB "logtest.db"
#define WIPS_EID_MAX 10
#define WIPS_EID_ACTION_GRP 8
#endif

#include "event_sql_log.h"

#define EVENT_SQL_LOGGER_NODESIZE sizeof(struct event_sqllog_pkt)

struct event_sqllog_pkt {
	REPORT_VALUE_TYPE val;//wnode
	int type;//event type
	int logmode;
	struct timeval when_event_happen;
	int logDone;//bit 0:sqllog done, bit 1:syslog done
};

struct event_report_logger_control* __sql_logctl__=NULL;
char* __sql_filename__=NULL;
sig_atomic_t __sqllog_timeout_countdown__=EVENT_SQL_TIMEOUT_SECONDS;

#define REPORTSQL_MODEL "insert into wips_event (\"ssid\", \"name\", \"bssid\", \"mac\", \"channel\",\"alert\", \"permit\", \"pri\", \"id\", \"is_grp\", \"grp_id\", \"detect_time\") values(\"%s\", \"%s\", \"%s\", \"%s\", \"%d\", \"%s\", \"%d\", \"%s\", \"%d\", \"%d\", \"%d\", \"%s\")"
#define GEN_SQL_CODE(sqlbuffer, ssid, name, bssid, mac, channel, alert, block, pri, id, is_grp, grp_id, detect_time) sprintf(sqlbuffer, REPORTSQL_MODEL, ssid, name,  bssid, mac, channel, alert, block, pri, id, is_grp, grp_id, detect_time)
#define GEN_MAC_BY_ARRAY(macbuffer, intof6) sprintf(macbuffer, "%02x:%02x:%02x:%02x:%02x:%02x", intof6[0], intof6[1], intof6[2], intof6[3], intof6[4], intof6[5])
#define GEN_TIMESTR_BY_TIMEVAL(stimeval, timestrname) \
  char timestrname[100]; \
  {  struct tm* localtm=localtime(&(stimeval.tv_sec));	     \
     sprintf(timestrname, "%d-%02d-%02d %02d:%02d:%02d.%06ld",  \
     localtm->tm_year+1900, localtm->tm_mon+1, localtm->tm_mday, \
     localtm->tm_hour, localtm->tm_min, localtm->tm_sec, stimeval.tv_usec);}

static int report_ap_event_acext(struct event_sqllog_pkt* pkt, sqlite3* db)//acext means access extern variables
{

	char macbuffer[24];
	char sqlbuffer[512]="";
	REPORT_VALUE_TYPE* wnode=&(pkt->val);
	int event = pkt->type;
	int logmode = pkt->logmode;
	int retcode=0;//bit0: sqllog, bit1:syslog

	GEN_MAC_BY_ARRAY(macbuffer, wnode->mac);
	GEN_TIMESTR_BY_TIMEVAL(pkt->when_event_happen, detect_time);
	if( logmode==0 || logmode==1 ){ //log in sql
		if( db==NULL )  goto ap_sql_log_fail;
		if( (pkt->logDone & 0x1) == 0x1 ) goto ap_sql_log_success;
		if(event < WIPS_EID_MAX){
		  GEN_SQL_CODE(sqlbuffer, wnode->ssid, wnode->name, macbuffer, macbuffer, wnode->channel, wevent_list[event-1].name, wnode->block, wevent_list[event-1].pri, 
				   wevent_list[event-1].id,  wevent_list[event-1].is_grp, wevent_list[event-1].grp_id, detect_time);
		}else if(event > WIPS_EID_MAX){
		  GEN_SQL_CODE(sqlbuffer, wnode->ssid, wnode->name, macbuffer, macbuffer, wnode->channel, eve_pri_table[event-1].name, wnode->block, "提示", 
				   event,  0, WIPS_EID_ACTION_GRP, detect_time);
		}

		if( sqlite3_exec(db, sqlbuffer, NULL, NULL, NULL) != SQLITE_OK )  goto ap_sql_log_fail;  
	ap_sql_log_success:
		pkt->logDone |= 0x1;
		retcode |= 1;

		goto ap_sql_log_exit;
	ap_sql_log_fail:
		WIPSD_DEBUG("ERROR: %s", sqlite3_errmsg(db));
		retcode &= ~1;
	}
ap_sql_log_exit:
	if ( logmode==0 || logmode== 2 ){ //log in sys
		if( (pkt->logDone & 0x2) == 0x2) goto ap_sys_log_success;

		int log_pri = eve_pri_table[event -1].pri;
		char* pbuf = prepare_log_data(wnode, event, log_pri);
		if(pbuf==NULL) goto ap_sys_log_fail;
		log_pri = wips_dm[EVENT].fac  * 8  + log_pri;
		syslog(log_pri, "%s", pbuf);
		wipsd_free(pbuf);
	ap_sys_log_success:
		pkt->logDone |= 2;
		retcode |= 2;
		goto ap_sys_log_exit;
	ap_sys_log_fail:
		retcode &= ~2;
	}
ap_sys_log_exit:
	return retcode;
} 
  
static int report_sta_event_acext(struct event_sqllog_pkt* pkt, sqlite3* db)//acext means access extern variables
{
	char macbuffer[24];
	char sqlbuffer[512]="";
	REPORT_VALUE_TYPE* wnode=&(pkt->val);
	char bssid[24];
	int event = pkt->type;
	int logmode = pkt->logmode;
	int retcode=0;//bit0: sqllog, bit1:syslog

	GEN_MAC_BY_ARRAY(macbuffer, wnode->mac);
	GEN_MAC_BY_ARRAY(bssid, wnode->bssid);
	GEN_TIMESTR_BY_TIMEVAL(pkt->when_event_happen, detect_time);
	if(strncmp(bssid, "ff:ff:ff:ff:ff:ff", 17) == 0){
		sprintf(bssid, "未关联");
		memset(wnode->ssid, 0, sizeof(&wnode->ssid));
	}
	if( logmode==0 || logmode==1 ){ //log in sql
		if( db==NULL )  goto sta_sql_log_fail;
		if( (pkt->logDone & 0x1) == 0x1 ) goto sta_sql_log_success;
		if(event < WIPS_EID_MAX){
		  GEN_SQL_CODE(sqlbuffer, wnode->ssid, wnode->name, bssid, macbuffer, wnode->channel, wevent_list[event-1].name, wnode->block, wevent_list[event-1].pri, 
				   wevent_list[event-1].id,  wevent_list[event-1].is_grp, wevent_list[event-1].grp_id, detect_time);
		}else if( event > WIPS_EID_MAX){
		  GEN_SQL_CODE(sqlbuffer, wnode->ssid, wnode->name, bssid, macbuffer, wnode->channel, eve_pri_table[event-1].name, wnode->block, "提示", 
				   event,  0, WIPS_EID_ACTION_GRP, detect_time);
		}
		
		if( sqlite3_exec(db, sqlbuffer, NULL, NULL, NULL) != SQLITE_OK )  goto sta_sql_log_fail;  
	sta_sql_log_success:
		pkt->logDone |= 0x1;
		retcode |= 1;
		goto sta_sql_log_exit;
	sta_sql_log_fail:
		WIPSD_DEBUG("ERROR: %s", sqlite3_errmsg(db));
		retcode &= ~1;
	}
 sta_sql_log_exit:

	if ( logmode==0 || logmode== 2 ){ //log in sys
       		if( (pkt->logDone & 0x2) == 0x2) goto sta_sys_log_success;
		int log_pri = eve_pri_table[event -1].pri;
		char* pbuf = prepare_log_data(wnode, event, log_pri);
		if(pbuf==NULL) goto sta_sys_log_fail;
		log_pri = wips_dm[EVENT].fac  * 8  + log_pri;
		syslog(log_pri, "%s", pbuf);
		wipsd_free(pbuf);
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

static int report_all_event_acext(struct event_sqllog_pkt* pkt, sqlite3* db)//acext means access extern variables
{
	sqlite3 *sql_wips_log = NULL;
	REPORT_VALUE_TYPE* node=&(pkt->val);
	int retvalue=0;
	int ret = 0;
	int row=0,col=0,num;
	char **dbResult;
	char *errmsg;
	char query[256];

	ret = sqlite3_open(WIPS_LOG_DB, &sql_wips_log);
	if(ret != SQLITE_OK) {
		WIPSD_DEBUG("open sqlite table wips_log.db failed!");
		return ret;
	}
	
	sqlite3_get_row( sql_wips_log, "select * from wips_event", &dbResult, &row, &col, &errmsg);
	if(row > EVENT_SQL_MAX_NUM) {
		num = row - (EVENT_SQL_MAX_NUM * 80 / 100);
		memset(query, 0, sizeof(query));
		sprintf(query, "delete from wips_event where rowid in (select rowid from wips_event order by up_time asc limit %d)", num);
		sqlite3_exec(sql_wips_log, query, NULL, NULL , NULL);
		sqlite3_exec(sql_wips_log, "VACUUM", NULL, NULL , NULL);
	}

	if(sql_wips_log){
		sqlite3_close(sql_wips_log);
	}

	if((node->node_type & 0x01)==0x01){
		retvalue |= report_ap_event_acext(pkt, db);
	}
	
	if(node->node_type & 0x06){
		retvalue |= report_sta_event_acext(pkt, db);
	}

	return retvalue;
}

static int event_sql_logfunc_exmple(struct ring_control* buffer, int lognum)
{
	sqlite3* db;
	int savecount=0;
	int dbopenflag=0;

#define TRY_OPEN_DB(dbfilename, pdb, openflag)  {\
    if(openflag==0) {\
      if(sqlite3_open(dbfilename, &pdb)==SQLITE_OK) {\
        openflag = 1;\
      }else{\
       wipsd_sqlite3_close(pdb);\
       pdb = NULL; }}}

	TRY_OPEN_DB(__sql_filename__, db, dbopenflag);
	if( db==NULL ){
		WIPSD_DEBUG("TRY_OPEN_DB failed!.\n");
		goto clog_exit;
	}
	int i;
	if(sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL)!=SQLITE_OK){
		WIPSD_DEBUG("GET RESERVED LOCK FAIL");
		goto clog_exit;
	}
	for(i=0; i<lognum; i++){
		struct event_sqllog_pkt* pkt;
		if(  dequeue_ring(buffer, (void**)&pkt) != 0 ){
			int logDoneFlag=report_all_event_acext(pkt, db);
			if((logDoneFlag & 0x1)==0){ //Nothing Done
				break;
			}else{ // sql log success
				savecount++;
			}
		}else{ // dequeue error
			break;
		}
	}
	if(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL)!=SQLITE_OK && savecount>0){
		WIPSD_DEBUG("COMMIT FAIL, %d EVENT NOT SAVE", savecount);
		goto clog_exit;
	}

clog_exit:
	if(db!=NULL) wipsd_sqlite3_close(db);
	if(savecount>0) 
	  __sqllog_timeout_countdown__ = EVENT_SQL_TIMEOUT_SECONDS;
	return savecount;

}
#if 0
int init_event_sqllog(const char* dbfilename)
{
	int filenamelen = strlen(dbfilename)+1;
	__sql_filename__ = (char*)malloc(filenamelen);
	if( __sql_filename__ == NULL ) 
		return 1;
	strncpy(__sql_filename__, dbfilename, filenamelen>256?256:filenamelen);

	__sql_logctl__ = init_event_report_logger( EVENT_SQL_LOGGER_BUFFERSIZE, EVENT_SQL_LOGGER_NODESIZE, EVENT_SQL_LOGGER_GATE);
	if(__sql_logctl__==NULL)
		return 1;
	setlogfunc_event_report_logger(__sql_logctl__, event_sql_logfunc_exmple);
	return 0;
}
#endif
void delete_event_sqllog(void)
{
	if(__sql_logctl__!=NULL){
		delete_event_report_logger(__sql_logctl__);
		__sql_logctl__ = NULL;
	}
	if(__sql_filename__!=NULL){
		wipsd_free(__sql_filename__);
		__sql_filename__ = NULL;
	}
}

int flush_event_sqllog(void)
{
    return flush_event_report_logger(__sql_logctl__);
}

int tryflush_event_sqllog(void)
{
  if(--__sqllog_timeout_countdown__<=0 && __sql_logctl__!=NULL){
    __sqllog_timeout_countdown__ = EVENT_SQL_TIMEOUT_SECONDS;
    return flush_event_sqllog();
  }
  return 0;
}

int log_event_sqllog(REPORT_VALUE_TYPE* ap_val, int event, int logmode)
{
	struct event_sqllog_pkt __event_pkt__;
	__event_pkt__.val = *ap_val;
	__event_pkt__.type = event;
	__event_pkt__.logmode = logmode; //0:all, 1:sql, 2:sys
	__event_pkt__.logDone = 0;
	gettimeofday(&__event_pkt__.when_event_happen, NULL);{
	//before report
	char mac[24];
	char bssid[24];
	GEN_MAC_BY_ARRAY(mac, ap_val->mac);
	GEN_MAC_BY_ARRAY(bssid, ap_val->bssid);
	if((ap_val->node_type & 0x01)==0x01){
		WIPSD_DEBUG("MAC=%s, BSSID=%s, SSID=%s", mac, mac, ap_val->ssid);
	}
	if(ap_val->node_type & 0x06){
		WIPSD_DEBUG("MAC=%s, BSSID=%s, SSID=%s", mac, bssid, ap_val->ssid);
	}
	}
	int retcode=tellto_event_report_logger(__sql_logctl__, &__event_pkt__);
	return retcode;
}

#ifdef DEBUG_UNIT
void timer()
{ tryflush_event_sqllog(); 
  DRLT(0, 1, "TIME LEVEL: %d", __sqllog_timeout_countdown__);}
int main(int argn, char* argv[])
{
  sqlite3* db;
  system("touch logtest.db");
  sqlite3_open("logtest.db", &db);
  sqlite3_exec(db, "create table wips_event(bssid, mac, channel, alert, permit, pri, id, is_grp, grp_id, detect_time);", NULL, NULL, NULL);
  wipsd_sqlite3_close(db);

  init_event_sqllog("logtest.db");
  REPORT_VALUE_TYPE x={ .ssid={"00:23:45:67:89:ab"}, .node_type=1 };
  signal(SIGALRM, timer);
  struct itimerval timerval={.it_interval.tv_sec=0, .it_interval.tv_usec=500000, .it_value.tv_sec=0, .it_value.tv_usec=500000};
  setitimer(ITIMER_REAL, &timerval, NULL);
  int i;
  for(;;){
    log_event_sqllog(&x, 1, 1);
    for(i=0;i<1000000;i++);
    sleep(1);
  }
  sleep(1);
  delete_event_sqllog();
  return 0;
}
#endif
#endif
