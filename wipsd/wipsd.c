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
#include <linux/ksyn_url.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
//#include <sqlite3.h>
#include "hash.h"
#include "ieee80211.h"
#include "sqlite3.h"
#include "wipsd_wnode.h"
#include "wipsd.h"
#include "checklist.h"
//#include "ppclient.h"
#include "sys/lfd_log.h"
#include "sys/serno_load.h"
#include "sys/wipsd_save.h"
#include "sys/hls_config_util.h"
#include "sys/hls_config.h"
#include "fakeap.h"
#include "wipsd_hook.h"
#include "buildtree.h"
#include "subnet_hash.h"
#include "wgate_hash.h"
#include "dobj_wgate.h"
#include "debug.h"
#ifdef MEMLOG
#include "event_mem_log.h"
#include <sys/shm.h>
#include <sys/stat.h>
#include "memshare.h"
#else
#include "event_sql_log.h"
#endif
#include "../../../kernel/include/linux/netfilter_ipv4/fw_objects.h"

#include "wipsd_pub.h"
#include "wipsd_vty.h"
#include "wipsd_sql.h"

#include "wipsd_interface.h"
#include "wipsd_parse.h"


#define P(x) ((x != NULL)?(x):"")
#define MSG_SIZE 1024
#define STALE 30
#define PATH "/tmp/wireless_s"
#define NMACQUAD(addr) \
	((unsigned char *)addr)[0], \
	((unsigned char *)addr)[1], \
	((unsigned char *)addr)[2], \
	((unsigned char *)addr)[3], \
	((unsigned char *)addr)[4], \
	((unsigned char *)addr)[5]

#define NMACQUAD_FMT "%02x:%02x:%02x:%02x:%02x:%02x"


typedef struct
{
	__u8 name[8];//
	long fd;//
	struct ifreq ifr;//
	struct sockaddr_ll addr;
	struct iwreq wrq;
	//rate,channel,txpower,
}interface_wlan;
interface_wlan if_sendwlan = {.fd=0};
interface_wlan if_wlan = {.fd=0};

#define FD_MAX 200
int fd_CMD[FD_MAX] = {0};

#ifdef WIPSD_DEBUGOUT
u8 wipsd_debug = WIPSD_CONFIG_DEBUG_ON;
#else
u8 wipsd_debug = WIPSD_CONFIG_DEBUG_OFF;
#endif

int show_all_infor = 0; /*????????station?????????*/

/*wireless config para*/
int wireless_enable	= 1;		/* 0:disable, 1:enable */
int wips_enbale		= 1;		/* 0:disable, 1:enable */
int monitor_band		= 2;		/* 2:2GHz, 5:5GHz, 25:2GHz& 5GHz */
int monitor_alert		= 0;		/* 0:all, 1:internal, 2:external */
int block_method		= 1;		/* 1:AP单向, 2:Sta单向, 3:双向, 4:自动/智能 */
int block_function	= 1|(1<<1);		/* bit 0:deauth, 	bit 1:arp*/
int multi_channel_block = 0;
int print_bt           = 0;

int channel_gap		= 50;		/* ms */
int wireless_node_age = 30;	/* s */ /*??wireless_node_age????? up_time*/
int wireless_node_dead_time = 300;   /*??wireless_node_dead_age???????*/
//int check_crack_time = 0;

int lan_mon_enable	= 1;		/* 0:disable, 1:enable */
int lan_mon_gap		= 5;		/* s */
int wips_sensitivity	= -96;	/* dBm */
char * AC_ip ="192.168.31.39";
int AC_port =WIPSD_SOCKET_PORT;
char lan_mon_if[128];
char lan_mon_net[128];
int active_lan_monitor = 1;

int update_blocking = 1;
int cur_freq		= 2;
int cur_channel	= 1;
pthread_mutex_t	chg_channel = PTHREAD_MUTEX_INITIALIZER;
int channel_index[CHANNEL_MAX_5G+1]={1,											//.1
						1,6,11,4,9,2,7,12,5,10,3,8,13,14,					//14
						184,185,186,187,188,189,192,196,					//8
						7,8,9,11,12,16,										//6
						34,36,38,40,42,44,46,								//7
						48,52,56,60,64,										//5
						100,104,108,112,116,120,124,128,132,136,140,	//11
						149,153,157,161,165									//5
						};														//[57:0-56]

struct tm *timep;
struct timeval ts;
time_t  otime;
long fresh_time = 0;
long wipsd_resend_info_age = 2;
int time_is_up = FALSE;

int tmp_t ;
extern int send_number;
extern int send_err_num;
int recv_packet=0;
int signal_threshold=0;
int blocking_number=0;
long long pth_number=0;
int blocked_node_numb =0;
int packet_syslog_out = 0;
int wips_event_syslog_out = 0;

int packet_counter = 0;
int suspend_package_num = WIPSD_SUSPENDING_PACKAGE_NUM;
int packet_counter4show = 0;
int check_packet_counter = 0;
int packet_timer = 0;

wipsd_hdr_t wipsd_hdr;
w_node_list * beacon_list_p = NULL;
w_node_list * beacon_list_tail = NULL;
w_node_list * sta_list_p = NULL;
w_node_list * sta_list_tail = NULL;
frame_control_t *fc1 ;
int heardaddr =26;
int fcs = 4;
char iface[9];

int  sniffering;

sqlite3 *sql_wconfig = NULL;


extern wpolicy_struct	*wpolicy_list;
extern wevent_struct	*wevent_list;
extern int wpolicy_index;
extern int wpolicy_num;
extern sqlite3 *sql_wconfig;

sta_node			*sta_list = NULL;
int wevent_grp_num = 0;
int wevent_listid = 0;

#if 0
int unsendpk_block_table_num = 0;
pthread_mutex_t	block_table_1_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	block_table_2_lock = PTHREAD_MUTEX_INITIALIZER;
block_sta_node  	*block_table_1[BLOCK_LIST_MAX_NUM];
block_sta_node  	*block_table_2[BLOCK_LIST_MAX_NUM];
block_sta_node  	**block_table = block_table_1;
#else
block_sta_node  	*block_table[BLOCK_LIST_MAX_NUM];
#endif

int wevent_index = 0;
int wevent_num = 0;

char ap_event[32];

int sta_index = 0;
int sta_num = 0;

/*char *all_sta_rates[] = {	"1","1.5","2","2.5","3","4.5","5.5","6","9","11","12","13.5","18",
	"22","24","27","33","36","48","54",NULL};*/
//	WIPSD_DEBUG("Supported rate -- 1|2|5.5|11|6|9|12|18|24|36|48|54 \n");
char *all_sta_rates[] = {	"1","2","5.5","6","9","11","12","18","24","36","48","54","NULL"};

int wpolicy_update_tag = 1;
int waction_update_tag = 1;
int wconfig_update_tag = 1;


int deauth_cmax=10;
int deauth_tmax=5;
int auth_cmax=20;
int auth_tmax=5;
int deassoc_cmax=10;
int deassoc_tmax=5;
int prob_req_cmax=30;
int prob_req_tmax=5;
int assoc_cmax=10;
int assoc_tmax=5;
int arp_cmax=100;
int arp_tmax=5;
int ack_cmax=60;
int ack_tmax=5;
int cts_cmax=80;
int cts_tmax=5;
int rts_cmax=80;
int rts_tmax=5;
//sem_t sem;
long SINGLE =22;
long NOISE =23;
long CHANNEL =18;
long RATE =17;
int SsidAgingTime_max = 10;

#define MAXLINES 600
//#define IW_ESSID_MAX_SIZE 50
// Globals
char ssidlist[MAXLINES][IW_ESSID_MAX_SIZE+1];
int count=0;
int f_enable =0;
struct w_node *w_tmp;
int fragframe = 0;
unsigned char fcflags = 0;
int cmd_highest_priority = 0;

short deau_seq = 0;
short deau_seq_en = 0;

int loop_counts = 0;
int maybe_net_fd;
struct rtnl_handle rth;
static struct thread * natfd_read_th=NULL;

//debug
int debug_wpackage_WIPSD_DEBUG_en	= 0;		/* 0:disable, 1:enable */
int debug_ap_number	= 0;
int debug_sta_number	= 0;
__u32 listask_polln = 0;

int cc = 1;

#define RE_CREATE_RECV_SOCKET 1234
int re_create_recv_socket = RE_CREATE_RECV_SOCKET;
//static int handle_sig2 = 1;
struct thread_master *master = NULL;
struct zclient *zclient = NULL;
struct wipsd_interface_hdr *wipsd_itf_list = NULL;
extern void wipsd_init_vty(void);
extern void wipsd_if_register(void);

#if 0
#ifdef MIPS
void tree_get_attack_list(ListBuf* treebuf);
extern int flush_event_memlog(void);
#endif
#endif

//extern int ppclient_enable;

struct timeval old_test, new_test;

struct list_tast *block_tast_head = NULL;
struct list_tast *block_tast_rear = NULL;

struct list_tast *PKG_tast_head = NULL;
struct list_tast *PKG_tast_rear = NULL;
pthread_mutex_t PKG_task_lock = PTHREAD_MUTEX_INITIALIZER;
int PKG_num = 0;
static int handle_flag = 1;
struct hash_control *wlist_hash_table;
struct hash_control *nodeinfo_hash_table;

extern int find_internal_ssid(char *ssid);
extern int init_vendor_hash_table(void);
extern int destory_vendor_hash_table(void);
extern char *find_mac_vendor(char *mac);
extern char *find_lan_ip(char *mac, char **ip);
extern int do_active_lan_mon_period(void);
extern int cmd_intelid;
extern void deauth_blocking(interface_wlan *piface,__u8 *pds,__u8 *psa,__u8 *pbssid,
						long rate, short seq, __u8 reason, short method);
extern void arp_attack_blocking(interface_wlan *piface, __u8 *bssid, __u8 *psrcmac, __u8 *pdstmac,
				__u8 *psrcip, __u8 *pdstip, int istods);
static int find_wlistnode_sniffer(struct w_node * wnode, int task_type,
		int (*func)(struct w_node * latest,struct w_node * exist) );
static int wipsd_check_ieee80211_data(u8 *buf, int len, u8 fc02, u8 fc1, struct w_node *sta_val);
static int init_database(void);
static int add_wlistnode( w_node_list * p_oflist, w_node_list ** header, w_node_list ** tail);
int get_wlist_node(char * mac, struct w_node ** node_frame);
static w_node_list * update_sta_node_waction( w_node_list * p_oflist,
	w_node_list ** header, w_node_list ** tail,ListBuf * treebuf);
static int update_sta_waction(w_node_list ** header, w_node_list ** tail,ListBuf * treebuf);
//int check_beacon_ssidAgingTime(struct w_node * exist);
int event_count(int * count,int c_max, int * interval, int inter_max);
int report_wips_event(struct w_node *node, int event);
int node_changed(struct w_node * old_node, int task_type);
int sniffer(interface_wlan * piface);
int insert_PKG(__u8 *buf, int len);


#if 1
pthread_mutex_t lock;
pthread_mutex_t dev_lock;

int log_mode;/*0:all,1:local syslog,2:remote syslog*/
unsigned int syslog_ip;
unsigned short syslog_port;
//static char dev_ipaddr[64] = {'\0'};
//static char dev_mac[24] = {'\0'};
//static char interface_name[32];
static char (*dic_table)[512];


typedef struct key_word KW;
static KW kw[] = {
		{
		.name = "SerialNUM",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "GenTime",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "EvtCount",
		.kw_type = DIGITAL,
		.maxsize = 16,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "EventID",
		.kw_type = DIGITAL,
		.maxsize = 16,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "Content",
		.kw_type = STRING,
		.maxsize = 512,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "WipsIP",
		.kw_type = STRING,
		.maxsize = 24,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "WipsMAC",
		.kw_type = STRING,
		.maxsize = 24,
		.grp = LOG_ALL,
		.meaning = ""
		},{
		.name = "WEBssid",
		.kw_type = STRING,
		.maxsize = 24,
		.grp = LOG_EVENT,
		.meaning = ""
		},{
		.name = "WESsid",
		.kw_type = STRING,
		.maxsize = 64,
		.grp = LOG_EVENT,
		},{
		.name = "WEMAC",
		.kw_type = STRING,
		.maxsize = 24,
		.grp = LOG_EVENT,
		},{
		.name = "WEWMAC",
		.kw_type = STRING,
		.maxsize = 24,
		.grp = LOG_EVENT,
		},{
		.name = "WEProtocol",
		.kw_type = STRING,
		.maxsize = 8,
		.grp = LOG_EVENT,
		},{
		.name = "WEDevType",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_EVENT,
		},{
		.name = "WESecurity",
		.kw_type = STRING,
		.maxsize = 48,
		.grp = LOG_EVENT,
		},{
		.name = "WEChannel",
		.kw_type = DIGITAL,
		.maxsize = sizeof(int),
		.grp = LOG_EVENT,
		},{
		.name = "WESignal",
		.kw_type = STRING,
		.maxsize = 4,
		.grp = LOG_EVENT,
		},{
		.name = "WENoise",
		.kw_type = STRING,
		.maxsize = 4,
		.grp = LOG_EVENT,
		},{
		.name = "WERates",
		.kw_type = DIGITAL,
		.maxsize = 4,
		.grp = LOG_EVENT,
		},{
		.name = "WEIPAddr",
		.kw_type = STRING,
		.maxsize = 24,
		.grp = LOG_EVENT,
		},{
		.name = "WEVendor",
		.kw_type = STRING,
		.maxsize = 128,
		.grp = LOG_EVENT,
		},{
		.name = "WEUptime",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_EVENT,
		},{
		.name = "WELasttime",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_EVENT,
		},{
		.name = "WEGrpName",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_EVENT,
		},{
		.name = "WEEveName",
		.kw_type = STRING,
		.maxsize = 128,
		.grp = LOG_EVENT,
		},{
		.name = "WEBlkFlag",
		.kw_type = DIGITAL,
		.maxsize = sizeof(int),
		.grp = LOG_EVENT,
		},{
		.name = "WEPri",
		.kw_type = DIGITAL,
		.maxsize = 24,
		.grp = LOG_EVENT,
		},{
		.name = "WEObjName",
		.kw_type = STRING,
		.maxsize = 64,
		.grp = LOG_EVENT,
		},{
		.name = "WSTime",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_EVENT,
		},{
		.name = "WSType",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_SYSTEM,
		},{
		.name = "WSSource",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_SYSTEM,
		},{
		.name = "WSUser",
		.kw_type = STRING,
		.maxsize = 32,
		.grp = LOG_SYSTEM,
		},{
		.name = "WSinfo",
		.kw_type = STRING,
		.maxsize = 128,
		.grp = LOG_SYSTEM,
		},
		{0}
};

#if 0 
int wipsd_arp_find_mac(char* mac)
{

	int fd;
	char mem_tmp[1024];
	fd = open("/proc/net/arp",O_RDONLY);
	if(fd<0)
	{
		vsos_debug_out("func:%s ,open arp info error\n",__func__);
		return -1;
	}
#if 0
	arp_info_t = (char*)mmap(NULL,32,PROT_READ,MAP_PRIVATE,arp_fd,0);
	if(arp_info_t == NULL)
	{
		vsos_debug_out("func:%s,mmap arp info error\n",__func__);
//		close(fd);
		return -1;
	}

	arp_info= arp_info_t;
//	close(fd);
	return 0;
#endif	


	memset(mem_tmp,0,1024);
	read(fd,mem_tmp,1024);
	//WIPSD_DEBUG("find str:%s\t\n",mac);
	//WIPSD_DEBUG("get arp info:\n%s \t\n",mem_tmp);
	if(strstr(mem_tmp,mac)==NULL)
	{
		//WIPSD_DEBUG("Can not find str:%s\n",mac);
		close(fd);
		return 0;
	}else{
		//WIPSD_DEBUG("find str\n");
		close(fd);
		return 1;
	}
	
}
#endif
static int log_snprintf(struct log_buf *buf, int len, char *format, ...)
{
	va_list args;
	int ret;


	if (buf->offset >= buf->len)
		goto realloc;

retry:

	va_start(args, format);
	ret = vsnprintf(buf->buf + buf->offset, len, format, args);
	va_end(args);

	if (ret > -1 && ret < (buf->len - buf->offset)) {
		buf->offset += ret;
		buf->buf[buf->offset] = 0;
		goto out;
	}

realloc:

	buf->buf = realloc(buf->buf, (buf->len + 1) * 2);
	assert(buf->buf);
	buf->len = (buf->len + 1) * 2 - 1;

	goto retry;

out:


	return 0;
}

#if 0
static int lfd_get_dev_para(IN const char *shell, \
							OUT char *para)
{
	char *cmd;
	FILE *fp;
	int rv;

	if(!para)return -1;

	cmd = malloc(128);
	if(cmd == NULL){
		WIPSD_DEBUG("mallc mem error \n");
		return -1;
	}

	memset(cmd,0,128);

	snprintf(cmd,128,shell);

	fp = popen(cmd, "r");
	if(fp == NULL){
		WIPSD_DEBUG("Popen error \n");
		free(cmd);
		return -1;
	}
	rv = fread((void *)para,1, 128,fp);
	if(rv <= 0){
		WIPSD_DEBUG("fread error \n");
		pclose(fp);
		free(cmd);
		return -1;
	}

	/*
	while(1){
		if(para[i++] == '#' || para[i++] =='\0' ){
		para[i] = '\0';
		break;
		}
	}*/

	para[strlen(para) -1] = '\0';
	free(cmd);
	pclose(fp);
	return 0;
}
#endif

#endif

struct hash_control *hotspot_hash_table;
// Search for the given ESSID in the populated list of hotspot essid's
// Return 0 if there is a match found, 1 if there are no matches.
int lookup_hotspot(char *name)
{
	// ssidlist is global
	int i=0;
	if(f_enable){
		if(	hash_find(hotspot_hash_table, (const char *)name, 0) != NULL){
			return(0);
		}else{
			return(1);
		}
		for (i=0; i < count; i++){
			// Compare against the list from given ssid file
			// this list include default essids from inencrypted hotspots
			// and default essid's
			if (strncmp (name, ssidlist[i], strlen(ssidlist[i])) == 0){
				return(0);
			}
		}
	}

	// No matches found
	return(1);
}

__u8 atoix(__u8 * str)
{
	if(*str > 47 && *str < 58) return (*str - 48);
	if(*str > 64 && *str < 71) return (*str - 55);
	if(*str > 96 && *str < 103) return (*str - 87);

	return 0;
}

void str2mac(__u8 * mac, char * str1)
{
    __u8 *  str = (__u8 * )str1;
	mac[0]=atoix(&str[0])*16 + atoix(&str[1]);
	mac[1]=atoix(&str[3])*16 + atoix(&str[4]);
	mac[2]=atoix(&str[6])*16 + atoix(&str[7]);
	mac[3]=atoix(&str[9])*16 + atoix(&str[10]);
	mac[4]=atoix(&str[12])*16 + atoix(&str[13]);
	mac[5]=atoix(&str[15])*16 + atoix(&str[16]);
}

/*static  void set_wevent_bitmap(int eid, uint64_t* ev_map)
{
		ev_map[0] |= ( 1ULL << eid);
}*/

//uint64_t set_wevent_bitmap(int eid, uint64_t ev_map)
static  __u32 set_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] )
{
	int index;
	index = eid / 32;
	eid = eid % 32;
	if(index < ALERT_LEN)
		return ((*ev_map)[index] |= ( 1UL << eid));
	else
		return 0xffffffff;
}

//uint64_t clear_wevent_bitmap(int eid, uint64_t ev_map)
static  __u32 clear_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] )
{
	int index;
	index = eid / 32;
	eid = eid % 32;
	if(index < ALERT_LEN)
		return ((*ev_map)[index] &= ~( 1UL << eid));
	else
		return 0xffffffff;
}

//static uint64_t test_wevent_bitmap(int eid, uint64_t* ev_map)
__u32 test_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] )
{
	int index;
	index = eid / 32;
	eid = eid % 32;
	if(index < ALERT_LEN)
		return ((*ev_map)[index] & ( 1UL << eid));
	else
		return 0;
}

static int lookup_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] )
{
	int i;

	if(wevent_list[eid-1].is_grp == 0) {			//not group

		if(test_wevent_bitmap(eid, ev_map) > 0)
			return 1;
	}
	else if(wevent_list[eid-1].is_grp == 1) {	//is group

		for(i = eid; i < WIPS_EID_MAX-1; i++) {
			if(wevent_list[i].is_grp != 0)		//next group
				break;

			if(test_wevent_bitmap(i+1, ev_map) > 0)
				return 1;
		}
	}

	return 0;
}

int get_block_index_2g(int ch)
{
	switch(ch) {
		case 1:
				return 0;
		case 2:
				return 1;
		case 3:
				return 2;
		case 4:
				return 3;
		case 5:
				return 4;
		case 6:
				return 5;
		case 7:
				return 6;
		case 8:
				return 7;
		case 9:
				return 8;
		case 10:
				return 9;
		case 11:
				return 10;
		case 12:
				return 11;
		case 13:
				return 12;
		case 14:
				return 13;
		default:
				return 0;
	}

	WIPSD_DEBUG("Block channel error: %d\n",ch);
	return 0;
}

int get_block_index_5g(int ch)
{
	switch(ch) {
		case 7:
			return 14;
		case 8:
			return 15;
		case 9:
			return 16;
		case 11:
			return 17;
		case 12:
			return 18;
		case 16:
			return 19;
		case 34:
			return 20;
		case 36:
			return 21;
		case 38:
	   		return 22;
		case 40:
	   		return 23;
		case 42:
	   		return 24;
		case 44:
	   		return 25;
		case 46:
	   		return 26;
		case 48:
	   		return 27;
		case 52:
	   		return 28;
		case 56:
	   		return 29;
		case 60:
	   		return 30;
		case 64:
	   		return 31;
		case 100:
	   		return 32;
		case 104:
	   		return 33;
		case 108:
	   		return 34;
		case 112:
	   		return 35;
		case 116:
	   		return 36;
		case 120:
	   		return 37;
		case 124:
	   		return 38;
		case 128:
	   		return 39;
		case 132:
	   		return 40;
		case 136:
	   		return 41;
		case 140:
	   		return 42;
		case 149:
	   		return 43;
		case 153:
	   		return 44;
		case 157:
	   		return 45;
		case 161:
	   		return 46;
		case 165:
	   		return 47;
		case 183:
	   		return 48;
		case 184:
	   		return 49;
		case 185:
	   		return 50;
		case 187:
	   		return 51;
		case 188:
	   		return 52;
		case 189:
	   		return 53;
		case 192:
	   		return 54;
		case 196:
	   		return 55;
		default:
			  return 0;
	}

		WIPSD_DEBUG("Block channel error: %d\n",ch);
	return 47;
}

#ifndef MASTER_CHANNEL
#define MASTER_CHANNEL 0
#endif

#ifndef AUXILIARY_CHANNEL
#define AUXILIARY_CHANNEL 1
#endif
#if 0
int add_one_block_node(struct w_node *nd,  char *mac, char *bssid,
	int freq, int ch, int auxiliary_channel, __u8* ipv4)
{
	block_sta_node *bnode, *tmpnode;
	int index;

	if(ch == 0) return 1;
	if(freq == 5)
		index = get_block_index_5g(ch);
	else
		index = get_block_index_2g(ch);

	tmpnode = block_table[index];
	while(tmpnode) {
		if(strncmp(tmpnode->mac, mac, 17) == 0
			&& strncmp(tmpnode->bssid, bssid, 17) == 0
			&& tmpnode->channel == ch)
		{
			//WIPSD_DEBUG("node exist,return!  sta:%s ap:%s ch:%s \n", mac,bssid,channel);
		   	tmpnode->hit = 1;
			return 1; /* node exist */
		}

		tmpnode = tmpnode->next;
	}

	bnode = calloc(1, sizeof(struct block_sta_node));
	strncpy(bnode->mac, mac, 17);
	strncpy(bnode->bssid, bssid, 17);
	memcpy(bnode->addr_ipv4, ipv4, 4);
	bnode->channel = ch;
	bnode->mac[17] = '\0';
	bnode->bssid[17] = '\0';
	bnode->next = NULL;
	bnode->prev = NULL;
	bnode->tail = NULL;
	bnode->head = NULL;
	bnode->block_count = 0;
	bnode->block_method	=	0x1;
	bnode->hit = 1;
	bnode->auxiliary_channel = auxiliary_channel;
	if(block_table[index] == NULL) {
		block_table[index] = bnode;
		block_table[index]->tail = bnode;
	}
	else {
		tmpnode = block_table[index]->tail;
		tmpnode->next = bnode;
		bnode->prev = tmpnode;
		block_table[index]->tail = bnode;
	}

	return 0;
}

int add_one_arpblock_node(nodeInfo_2beBlock* node, int freq, int ch, int auxiliary_channel)
{
	block_sta_node *bnode, *tmpnode;
	int index;
	char mac[24];
	char bssid[24];

	if(ch == 0) return 0;
	if(freq == 5)
		index = get_block_index_5g(ch);
	else
		index = get_block_index_2g(ch);

//	if(0 != pthread_mutex_trylock(&block_table_lock)) return 0;
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", node->mac[0], node->mac[1], node->mac[2], node->mac[3], node->mac[4], node->mac[5]);
	sprintf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x", node->bssid[0], node->bssid[1], node->bssid[2],
			node->bssid[3], node->bssid[4], node->bssid[5]);

	tmpnode = block_table[index];
	while(tmpnode != NULL) {
		if(strncmp(tmpnode->mac, mac, 17) == 0
			&& strncmp(tmpnode->bssid, bssid, 17) == 0
			&& tmpnode->channel == ch
			&& memcmp(tmpnode->gate_ip, node->wgate_ipv4, 4)==0
			&& memcmp(tmpnode->gate_mac, node->wgate_mac, 6)==0
			&& memcmp(tmpnode->addr_ipv4, node->ipv4, 4)==0
			&& tmpnode->block_method==node->block_method)
		{
			//WIPSD_DEBUG("node exist,return!  sta:%s ap:%s ch:%s \n", mac,bssid,channel);

		   		tmpnode->hit = 1;
//			pthread_mutex_unlock(&block_table_lock);

			return 0; /* node exist */
		}

		tmpnode = tmpnode->next;
	}

	bnode = calloc(1, sizeof(struct block_sta_node));

	strncpy(bnode->mac, mac, 17);
	strncpy(bnode->bssid, bssid, 17);
	bnode->channel = ch;
	bnode->mac[17] = '\0';
	bnode->bssid[17] = '\0';
	bnode->block_count = 0;

	bnode->next = NULL;
	bnode->prev = NULL;
	bnode->tail = NULL;
	bnode->head = NULL;

	bnode->block_method	=	0x2;
	memcpy(bnode->addr_ipv4, node->ipv4, 4);
	memcpy(bnode->gate_mac, node->wgate_mac, 6);
	memcpy(bnode->gate_ip, node->wgate_ipv4, 4);

	bnode->hit = 1;
	bnode->auxiliary_channel = auxiliary_channel;

	if(block_table[index] == NULL) {
		block_table[index] = bnode;
		block_table[index]->tail = bnode;
	}
	else {
		tmpnode = block_table[index]->tail;
		tmpnode->next = bnode;

		bnode->prev = tmpnode;
		block_table[index]->tail = bnode;
	}
//	pthread_mutex_unlock(&block_table_lock);
	return 1;
}
#endif
#if 0
int add_arpblock_node(nodeInfo_2beBlock* node)
{
	 int rv = 0;

	if(node->bssid[0] == 0xff)
		return 0;

	if(!multi_channel_block || cur_freq == 5)
		rv |= add_one_arpblock_node(node, cur_freq, node->channel, MASTER_CHANNEL);
	else {
		switch(node->channel) {
		case 1:
			rv |= add_one_arpblock_node(node, cur_freq, 1, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 2, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 3, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 4, AUXILIARY_CHANNEL);
			break;
		case 2:
		  if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 1, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 2, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 3, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 4, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 5, AUXILIARY_CHANNEL);
			break;
		case 3:
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 1, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 2, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 3, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 4, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 5, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 6, AUXILIARY_CHANNEL);
			break;
		case 4:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 1, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 2, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 3, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 4, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 5, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 6, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 7, AUXILIARY_CHANNEL);
			break;
		case 5:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 2, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 3, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 4, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 5, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 6, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 7, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 8, AUXILIARY_CHANNEL);
			break;
		case 6:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 3, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 4, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 5, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 6, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 7, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 8, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 9, AUXILIARY_CHANNEL);
			break;
		case 7:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 4, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 5, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 6, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 7, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 8, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 9, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 10, AUXILIARY_CHANNEL);
			break;
		case 8:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 5, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 6, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 7, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 8, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 9, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 10, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 11, AUXILIARY_CHANNEL);
			break;
		case 9:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 6, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 7, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 8, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 9, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 10, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 11, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 12, AUXILIARY_CHANNEL);
			break;
		case 10:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 7, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 8, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 9, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 10, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 11, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 12, AUXILIARY_CHANNEL);
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 13, AUXILIARY_CHANNEL);
			break;
		case 11:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 8, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 9, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 10, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 11, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 12, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 13, AUXILIARY_CHANNEL);
			break;
		case 12:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 9, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 10, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 11, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 12, MASTER_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 13, AUXILIARY_CHANNEL);
			break;
		case 13:
			if(cc & (1 << 2))rv |= add_one_arpblock_node(node, cur_freq, 10, AUXILIARY_CHANNEL);
			if(cc & (1 << 1))rv |= add_one_arpblock_node(node, cur_freq, 11, AUXILIARY_CHANNEL);
			if(cc & (1 << 0))rv |= add_one_arpblock_node(node, cur_freq, 12, AUXILIARY_CHANNEL);
			rv |= add_one_arpblock_node(node, cur_freq, 13, MASTER_CHANNEL);
			break;
		case 14:
			rv |= add_one_arpblock_node(node, cur_freq, 14, MASTER_CHANNEL);
			break;

		default:
			break;
		}
	}

//    if(rv > 0)
//    	report_wips_event(nd, WIPS_EID_STA_BLOCK_START);
#ifdef DEBUG_WIPSD
	if(rv>0){
#define print_mac(mac) WIPSD_DEBUG("%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5])
#define print_ip(ip) WIPSD_DEBUG("(%d.%d.%d.%d)",ip[0],ip[1],ip[2],ip[3])
	  WIPSD_DEBUG("add arpblock node ");
	  print_mac(node->mac);print_ip(node->ipv4);
	  WIPSD_DEBUG("\n\tbssid ");
	  print_mac(node->bssid);WIPSD_DEBUG("[%d]", node->channel);
	  WIPSD_DEBUG("\n\twgate ");
	  print_mac(node->wgate_mac);print_ip(node->wgate_ipv4);
	  WIPSD_DEBUG("\n");
	}
#endif

	return 0;
}
#endif
# if 0
int add_block_node(struct w_node *nd, char *mac, char *bssid, int channel, __u8 cur_freq, __u8* ipv4)
{
    int rv = 0;

	if(mac[0] == '\0' || bssid[0] == '\0')
		return 0;

	if(bssid[0] == 'f' && bssid[1] == 'f')
		return 0;

	if(bssid[0] == 'F' && bssid[1] == 'F')
		return 0;

	rv = add_one_block_node(nd, mac, bssid, cur_freq, channel, MASTER_CHANNEL,ipv4);
	if(rv){
		//WIPSD_DEBUG("add block node failed! sta:%s ap:%s channel[%d] \n", mac, bssid, channel);
	}

	return 0;
}

int del_one_block_node(struct w_node *nd, char *mac, char *bssid, int freq, int index)
{
    int rv = 0;
	block_sta_node *tmpnode, *nextnode;

//	if(0 != pthread_mutex_trylock(&block_table_lock)) return 0;

	tmpnode = block_table[index];
	while(tmpnode != NULL) {

		if(strncmp(tmpnode->mac, mac, 17) == 0
			/*&& strncmp(tmpnode->bssid, bssid, 17) == 0*/)
		{
#ifdef DEBUG_WIPSD
		  WIPSD_DEBUG("del block node!  sta:%s ap:%s channel[%d] %s\n", mac,tmpnode->bssid, index+1, tmpnode->block_method==0x2 ? "arp block" : (tmpnode->block_method==0x1?"deauth block":"unknown block"));
#endif
			if(tmpnode->next == NULL && tmpnode->prev == NULL) {		//only one
				wipsd_free(tmpnode);
				block_table[index] = NULL;

//				pthread_mutex_unlock(&block_table_lock);
				return 1;
			}
			else if(tmpnode->next == NULL && tmpnode->prev != NULL) {	//it's tail
				tmpnode->prev->next = NULL;
				block_table[index]->tail = tmpnode->prev;
				wipsd_free(tmpnode);

//				pthread_mutex_unlock(&block_table_lock);
				return 1;
			}
			else if(tmpnode->next != NULL && tmpnode->prev == NULL) {	//it's first node
				block_table[index] = block_table[index]->next;
				block_table[index]->prev = NULL;
				block_table[index]->tail = tmpnode->tail;
				wipsd_free(tmpnode);
				tmpnode = block_table[index];
                rv = 1;
				continue;
			}
			else {													//normal node
				//WIPSD_DEBUG("tmpnode->next:%d tmpnode->prev:%d  \n", (int)tmpnode->next, (int)tmpnode->prev);
				nextnode = tmpnode->next;
				tmpnode->next->prev = tmpnode->prev;
				tmpnode->prev->next = tmpnode->next;
				wipsd_free(tmpnode);
				tmpnode = nextnode;
                rv = 1;
				continue;
			}
		}

		tmpnode = tmpnode->next;
	}
//	pthread_mutex_unlock(&block_table_lock);
	return rv;
}
#endif
#if 0
int del_block_node(struct w_node *nd, char *mac, char *bssid)
{
	int i, rv = 0;

	if(mac[0] == '\0' || bssid[0] == '\0'  )
		return 0;

//	WIPSD_DEBUG("begin del block node!  sta:%s ap:%s  \n", mac,bssid);
/*
	if(cur_freq == 5) {
		for(i=BLOCK_LIST_MAX_NUM_2G; i<BLOCK_LIST_MAX_NUM; i++) {
			rv |= del_one_block_node(nd, mac, bssid, cur_freq, i);
		}
	}
	else {
		for(i=0; i<BLOCK_LIST_MAX_NUM_2G; i++) {*/
		for(i=0; i<BLOCK_LIST_MAX_NUM; i++) {
			rv |= del_one_block_node(nd, mac, bssid, cur_freq, i);
		}
//	}

//    if(rv > 0)
//        report_wips_event(nd, WIPS_EID_STA_BLOCK_STOP);


//	WIPSD_DEBUG("end del block node!  sta:%s ap:%s  \n", mac,bssid);

	return 0;
}
#endif
int init_block_table(void)//block_table_1_lock: locked block_table_2_lock: unlocked
{
#if 0
	int i;
	pthread_mutex_lock(&block_table_1_lock);
	pthread_mutex_lock(&block_table_2_lock);

	for(i=0; i<BLOCK_LIST_MAX_NUM; i++) {
			block_table_1[i] = NULL;
			block_table_2[i] = NULL;
	}

	pthread_mutex_lock(&block_table_lock);
	block_table = block_table_1;
	unsendpk_block_table_num = 1;
	pthread_mutex_unlock(&block_table_lock);

	pthread_mutex_unlock(&block_table_2_lock);
	return 0;
#else
	return 0;
#endif

}
#if 0
int destory_block_table(void)
{
	block_sta_node *tmpnode = NULL;
	int i;

	for(i=0; i<BLOCK_LIST_MAX_NUM; i++) {
		if (block_table[i] != NULL){
			while(block_table[i]->tail != NULL) {
				tmpnode = block_table[i]->tail;

				if(tmpnode->prev != NULL)
					block_table[i]->tail = tmpnode->prev;
				else
					block_table[i]->tail = NULL;

				wipsd_free(tmpnode);
			}
			block_table[i] = NULL;
		}
	}

/*	if(block_table != NULL) {
		wipsd_free(block_table);
		block_table = NULL;
	}*/

	return 0;
}

int destory_block_tablexxx(void)
{
	block_sta_node *tmpnode=NULL;
	block_sta_node *tmpnodeNext=NULL;
	int i;

	for(i=0; i<BLOCK_LIST_MAX_NUM; i++) {
		tmpnode = block_table[i];
		block_table[i] = NULL;
		if(tmpnode){
			tmpnodeNext = tmpnode->next;
			wipsd_free(tmpnode);
			while(tmpnodeNext != NULL) {
				tmpnode = tmpnodeNext;
				tmpnodeNext = tmpnodeNext->next;
				wipsd_free(tmpnode);
			}
		}else{
		}
	}

	return 0;
}
#endif
int get_wevent(void* data, int n_columns, char** column_values, char** column_names)
{
	if(wevent_index >= wevent_num)
		return 0;

	wevent_list[wevent_index].id = atoi(column_values[0]);
	wevent_list[wevent_index].is_grp = atoi(column_values[1]);
	wevent_list[wevent_index].grp_id = atoi(column_values[2]);

	if(column_values[3])
		strncpy(wevent_list[wevent_index].pri, column_values[3], 7);
	wevent_list[wevent_index].pri[7] = '\0';

	if(column_values[4])
		strncpy(wevent_list[wevent_index].name, column_values[4], WEVENT_NAME_LEN_L);
	wevent_list[wevent_index].name[WEVENT_NAME_LEN_L] = '\0';

	if(column_values[5])
		strncpy(wevent_list[wevent_index].cmd_name, column_values[5], WEVENT_NAME_LEN_L);
	wevent_list[wevent_index].cmd_name[WEVENT_NAME_LEN_L] = '\0';

	if(column_values[6])
			strncpy(dic_table[wevent_index], column_values[6], 512);
	//WIPSD_DEBUG("content = %s \n",dic_table[wevent_index]);

	wevent_index++;
	return 0;
}

int init_wevent_list(void)
{
	int ret,row=0,col=0;
	char **dbResult;
	char *errmsg;
	sqlite3 *sql = NULL;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite wconfig.db error !");
		return 0;
	}

	ret = sqlite3_get_row( sql, "select * from wevent", &dbResult, &row, &col, &errmsg);
	if(row > 0 ) {
		wevent_num = row;
		dic_table = malloc(row * 512);
		if(!dic_table){
			wipsd_sqlite3_close(sql);
			WIPSD_DEBUG("no memory!");
			return 0;
			}

#ifdef MIPS
		wevent_listid = shmget(IPC_PRIVATE, row*sizeof(struct wevent_struct), IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IROTH);
		wevent_list = shmat(wevent_listid, 0, 0);
		if(wevent_list==(void*)-1) {
			wipsd_sqlite3_close(sql);
			wevent_list = NULL;
			WIPSD_DEBUG("no memory!");
			return 0;
		}
#else
		wevent_list = calloc(row,sizeof(struct wevent_struct));
		if(!wevent_list) {
			sqlite3_close(sql);
			WIPSD_DEBUG("no memory!");
			return 0;
		}
#endif

		wevent_index = 0;
		ret = sqlite3_exec(sql, "select * from wevent", get_wevent, NULL,NULL);
		if(ret != SQLITE_OK)
			goto error;
	}
	else
		goto error;

#ifdef MIPS
	ret = sqlite3_get_row( sql, "select * from wevent where is_grp=\"1\"", &dbResult, &row, &col, &errmsg);
	wevent_grp_num = row - 1;
#endif

    if(sql)
        wipsd_sqlite3_close(sql);

	return 0;

error:
	wipsd_sqlite3_close(sql);
	return -1;
}
#if 0
int destory_wevent_list(void)
{
	if(wevent_list)
		wipsd_free(wevent_list);
	if(dic_table)
		wipsd_free(dic_table);

	wevent_list =  NULL;
	return 0;
}

#endif
char *convert_sta_rate(short rate)
{
//	int r = atoi(rate);

	switch(rate) {

		case 0:
			return "auto";
		case 2:   /*	1 Mb  */
			return "1";
		case 4:   /*	2 Mb  */
			return "2";
		case 11:  /*  5.5 Mb  */
			return "5.5";
		case 12:  /*	6 Mb  */
			return "6";
		case 13:  /*  6.5 Mb  */
			return "6.5";
		case 18:  /*	9 Mb  */
			return "9";
		case 22:  /*   11 Mb  */
			return "11";
		case 24:  /*   12 Mb  */
			return "12";
		case 26:  /*   13 Mb  */
			return "13";
		case 27:  /* 13.5 Mb  */
			return "13.5";
		case 36:  /*   18 Mb  */
			return "18";
		case 39:  /* 19.5 Mb  */
			return "19.5";
		case 48:  /*   24 Mb  */
			return "24";
		case 52:  /*   26 Mb  */
			return "26";
		case 54:  /* 27.0 Mb  */
			return "27";
		case 72:  /*   36 Mb  */
			return "36";
		case 78:  /*   39 Mb  */
			return "39";
		case 81:  /* 40.5 Mb  */
			return "40.5";
		case 96:  /*   48 Mb  */
			return "48";
		case 104: /*   52 Mb  */
			return "52";
		case 108: /*   54 Mb  */
			return "54";
		case 117: /* 58.5 Mb  */
			return "58.5";
		case 130: /*   65 Mb  */
			return "65";
		case 156: /*   78 Mb  */
			return "78";
		case 162: /*   81 Mb  */
			return "81";
		case 208: /*  104 Mb  */
			return "104";
		case 216: /*  108 Mb  */
			return "108";
		case 234: /*  117 Mb  */
			return "117";
		case 243: /* 121.5Mb  */
			return "121.5";
		case 260: /*  130 Mb  */
			return "130";
		case 270: /*  135 Mb  */
			return "135";
		case 300: /*  150 Mb  */
			return "150";
		case 324: /*  162 Mb  */
			return "162";
		case 432: /*  216 Mb  */
			return "216";
		case 486: /*  243 Mb  */
			return "243";
		case 540: /*  270 Mb  */
			return "270";
		case 600: /*  300 Mb  */
			return "300";

		default:
			return "Unknown";
	}

	return "Unknown";
}

short convert_sta_channel(short channel)
{

	switch(channel) {
		case 2412:
			return 1;
		case 2417:
			return 2;
		case 2422:
			return 3;
		case 2427:
			return 4;
		case 2432:
			return 5;
		case 2437:
			return 6;
		case 2442:
			return 7;
		case 2447:
			return 8;
		case 2452:
			return 9;
		case 2457:
			return 10;
		case 2462:
			return 11;
		case 2467:
			return 12;
		case 2472:
			return 13;
		case 2484:
			return 14;
		default:
			return channel;
	}
	return channel;
}


int reverse_sta_channel(int channel)
{

	switch(channel) {
		case 1:
			return 2412;
		case 2:
			return 2417;
		case 3:
			return 2422;
		case 4:
			return 2427;
		case 5:
			return 2432;
		case 6:
			return 2437;
		case 7:
			return 2442;
		case 8:
			return 2447;
		case 9:
			return 2452;
		case 10:
			return 2457;
		case 11:
			return 2462;
		case 12:
			return 2467;
		case 13:
			return 2472;
		case 14:
			return 2484;
		default:
			return channel;
	}

	return channel;
}


int sql_get_ap_event(void* data, int n_columns, char** column_values, char** column_names)
{
	if(column_values[0])
		strncpy(ap_event, column_values[0], 31);

	return 0;
}

int is_ip_pass_gate(__u8* gateip, __u8* staip,__u8 mask)
{
  __u8 bmask[4];
  int i=mask;
  unsigned long lmask=0x80000000;
  memset(bmask, 0, sizeof(bmask));
  while(mask>=2){
    lmask |= lmask>>1;
    mask--;
  }
  if(i>0){
    bmask[0] = (lmask>>24)&0xff;
    bmask[1] = (lmask>>16)&0xff;
    bmask[2] = (lmask>>8)&0xff;
    bmask[3] = (lmask)&0xff;
  }

  WIPSD_DEBUG("MASK: %d.%d.%d.%d\n", bmask[0], bmask[1], bmask[2], bmask[3]);
#define MASK_EQ(bit) ((bmask[bit]&staip[bit])==(bmask[bit]&gateip[bit]))
  return MASK_EQ(0)&&MASK_EQ(1)&&MASK_EQ(2)&&MASK_EQ(3);
}

#define QUERY_WGATE(mac) (memcmp((void *)mac,"\x00\x00\x00\x00\x00\x00",6)==0?NULL:query_wgate_hash(mac))
u8 *query_wgate_checkip(u8 *mac, u8 *ip)
{
	if(!memcmp((void *)mac,"\x00\x00\x00\x00\x00\x00",6))
		return NULL;

	return query_wgate_hash_with_ip(mac, ip);
}

void insertUpdataBlockTask(struct list_tast *mp)
{
	if(block_tast_rear == NULL && block_tast_head == NULL){
		block_tast_head=block_tast_rear=mp;
		mp->next=NULL;
	}else{
		mp->next=NULL;
		block_tast_rear->next=mp;
		block_tast_rear=mp;
	}
}
extern int wipsd_wpolicy_edit_obj_data(u32 pid, u8 *mac, int type, enum nl_op_type cmd);

int add_block_node_by_blocklist(int pid, struct w_node *sta, __u8* bssid, int channel, int freq_band)
{
	struct list_tast *mp=NULL;
	struct list_tast *mp1=NULL;
	nodeInfo_2beBlock *node=NULL;
	nodeInfo_2beBlock *node1=NULL;
	__u8* gateip;
	__u8 gateip_buf[6];
	struct wipsd_ipc_data ipc_data;

	if(sta == NULL || bssid == NULL || channel==0){
		WIPSD_DEBUG("(sta == NULL || bssid == NULL || channel==0)");
		return -1;
	}

	node = XMALLOC(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,sizeof(nodeInfo_2beBlock));
	mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
	if(!mp || !node){
		WIPSD_DEBUG("malloc for new block_updata_task err!\n");
		XFREE(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,node);
		XFREE(MTYPE_WIPS_DEBUG_MP_NODE,mp);
		return -1;
	}

	memset((void *)&ipc_data, 0, sizeof(ipc_data));
	memset(node,0,sizeof(nodeInfo_2beBlock));
	memset(mp,0,sizeof(struct list_tast));
	memcpy(node->mac, sta->mac, 6);
	memcpy(node->bssid, bssid, 6);
	node->channel = channel;
	node->freq_band = freq_band;

	memcpy(ipc_data.mac, sta->mac, 6);
	memcpy(ipc_data.bssid, bssid, 6);
	ipc_data.channel = channel;
	ipc_data.freq_band = freq_band;

	if(memcmp(sta->sec_type, "open-system", 10)!=0 &&
	   sta->sec_type[0]!='\x0'){//deauth block node
		node->block_method	=	0x1;
		sta->block_func = 0x1;
		ipc_data.block_method = WIPSD_BLOCK_BY_DEAUTH;
	}
	else { //open-system
		gateip = query_wgate_checkip(sta->gatemac, sta->addr_ipv4);
		if((gateip && is_ip_pass_gate(gateip, sta->addr_ipv4, (u8)gateip[4]))
			|| (!gateip && !dobj_wgate_query(sta->gatemac, gateip_buf)) ){//ap2 arp block node
				gateip	=	gateip==NULL ? gateip_buf : gateip;
			memcpy(node->wgate_ipv4, gateip, 4);
			memcpy(node->wgate_mac, sta->gatemac, 6);
			memcpy(node->ipv4, sta->addr_ipv4, 4);
			node->block_method = 0x2;
		#if 1
			memcpy(&ipc_data.wgate_ipv4, gateip, 4);
			memcpy(ipc_data.wgate_mac, sta->gatemac, 6);
			memcpy(&ipc_data.ipv4, sta->addr_ipv4, 4);
			ipc_data.block_method = WIPSD_BLOCK_BY_ARP;
		#endif
			sta->block_func |= 0x2;
		}
		else if((gateip && is_ip_pass_gate(gateip, sta->addr_ipv4, (u8)gateip[4])) ||
				(!gateip && !dobj_wgate_query(sta->bssid, gateip_buf))){//ap3 arp block node
		 	gateip	=	gateip==NULL ? gateip_buf : gateip;
			memcpy(node->wgate_ipv4, gateip, 4);
			memcpy(node->wgate_mac, sta->bssid, 6);
			memcpy(node->ipv4, sta->addr_ipv4, 4);
			node->block_method	=	0x2;

#if 1
			memcpy(&ipc_data.wgate_ipv4, gateip, 4);
			memcpy(ipc_data.wgate_mac, sta->bssid, 6);
			memcpy(&ipc_data.ipv4, sta->addr_ipv4, 4);
			ipc_data.block_method = WIPSD_BLOCK_BY_ARP;
#endif
			sta->block_func |= 0x2;
		}
		else {
			if(sta->block_func) {
				node->block_method	=	0x1;
				sta->block_func = 0x1;
				//ipc_data.block_method = WIPSD_BLOCK_BY_DEAUTH;
				ipc_data.block_method = block_method;
				if(pid)
					wipsd_block_by_lan(pid, sta, NL_ADD_ADDR_OBJ);

				wipsd_block_by_wireless(&ipc_data, sta, WIPSD_ADD_BLOCK_INFO);
				XFREE(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,node);
				XFREE(MTYPE_WIPS_DEBUG_MP_NODE,mp);
				return -1;
			}

			node->block_method	=	0x1;
			sta->block_func = 0x1;
		}
	}

	if((sta->block_func & 0x3) == 0x3) {
	node1 = XMALLOC(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,sizeof(nodeInfo_2beBlock));
	mp1 = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
		if(!mp1 || !node1){
			WIPSD_DEBUG("malloc for new block_updata_task err!\n");
				XFREE(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,node1);
				XFREE(MTYPE_WIPS_DEBUG_MP_NODE,mp1);
			return -1;
		}

		memcpy(node1, node, sizeof(nodeInfo_2beBlock));
		memcpy(mp1, mp, sizeof(struct list_tast));
		mp1->task_type= NO_ADD_NODE;//BLOCK_TASK_DEL_NODE;
		mp1->node = (void *)node1;
		sta->block_func = 0x2;
		insertUpdataBlockTask(mp1);
	}

	if(pid)
		wipsd_block_by_lan(pid, sta, NL_ADD_ADDR_OBJ);
	wipsd_block_by_wireless(&ipc_data, sta, WIPSD_ADD_BLOCK_INFO);
	mp->task_type= BLOCK_TASK_ADD_NODE;
	mp->node = (void *)node;
	insertUpdataBlockTask(mp);
	return 0;
}

int del_block_node_by_blocklist(int pid, struct w_node *nd, __u8 *mac, __u8 *bssid)
{
	struct list_tast *mp=NULL;
	nodeInfo_2beBlock *node=NULL;
	struct wipsd_ipc_data ipc_data;

	if(mac == NULL )
		return -1;

	node = XMALLOC(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,sizeof(nodeInfo_2beBlock));
	mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
	if(mp == NULL || node == NULL){
		WIPSD_DEBUG("malloc for new block_updata_task err!\n");
		XFREE(MTYPE_WIPS_DEBUG_NODEINFO_2BEBLOCK,node);
		XFREE(MTYPE_WIPS_DEBUG_MP_NODE,mp);
		return -1;
	}

	memset((void *)&ipc_data, 0, sizeof(ipc_data));
	memset(node,0,sizeof(nodeInfo_2beBlock));
	memset(mp,0,sizeof(struct list_tast));
	memcpy(node->mac, mac, 6);
	memcpy(ipc_data.mac, mac, 6);
	ipc_data.channel = nd->channel;
	mp->task_type= BLOCK_TASK_DEL_NODE;
	mp->node = (void *)node;
	if(pid)
	{
        if (bssid)
            wipsd_wpolicy_edit_obj_data(pid, bssid, AP_MAC, NL_DEL_ADDR_OBJ);
        if (mac)
            wipsd_wpolicy_edit_obj_data(pid, mac, STA_MAC, NL_DEL_ADDR_OBJ);
	}
	wipsd_block_by_wireless(&ipc_data, nd, WIPSD_DEL_BLOCK_INFO);
	insertUpdataBlockTask(mp);
	return 0;
}


int sta_walk_wpolicy(struct w_node *sta, struct w_node *ap)
{
	int i, j, essid_match, ap_match, sta_match, ctime_match, wevent_match, mask, mac_mask_error;
	int channel_match,ret;
//	struct w_node *ap = NULL;
	char mac[24], bssid[24];
	long cur_time = 0;
	struct wipsd_ipc_data ipc_data;
	int block = 0;


	if(!wpolicy_list)
	{
		//WIPSD_DEBUG("[%s:%d]: wipsd policy list is null!\n", __FUNCTION__, __LINE__);
		return 0;
	}

	if(( memcmp( sta->bssid, "\xff\xff\xff\xff\xff\xff", 6 ) == 0 )
		|| ( memcmp( sta->bssid, "\x00\x00\x00\x00\x00\x00", 6 ) == 0 ))
		return 0;
#if 1
	time((time_t *)&cur_time);
	if (cur_time - sta->send_info_timeout <= wipsd_resend_info_age){
		return 0;
	}
	sta->send_info_timeout = cur_time;
#endif

	sprintf(mac, NMACQUAD_FMT, NMACQUAD(sta->mac));
	sprintf(bssid, NMACQUAD_FMT, NMACQUAD(sta->bssid));

	for(i = 0; i < wpolicy_index; i++)
	{
		if(wpolicy_list[i].enable[0] == '\0'
			|| strncmp(wpolicy_list[i].enable, "false", 5) == 0
			|| wpolicy_list[i].ap_name[0] == '\0'
			|| wpolicy_list[i].sta_name[0] == '\0'
			|| wpolicy_list[i].wevent[0]  == '\0'
			|| wpolicy_list[i].waction[0] == '\0')
		{
			continue;
		}

		mac_mask_error = 0;
		if(wpolicy_list[i].sta_mac_mask[0] != '\0') {
			for(j=0; j<strlen(wpolicy_list[i].sta_mac_mask); j++)
				if(!isdigit(wpolicy_list[i].sta_mac_mask[j]))
					mac_mask_error = 1;
		}

		if(mac_mask_error)
			continue;

		essid_match = 0;
		ap_match = 0;
		sta_match = 0;
		wevent_match = 0;
		ctime_match = 0;
		channel_match = 0;

		if(wpolicy_list[i].channel == 0){
			channel_match = 1;
		}else{
			if(!ap){
				if(0 == get_wlist_node((char *)&sta->bssid[0], &ap)) {
					if(wpolicy_list[i].channel == channelieee_convert(0, ap->freq_band, ap->channel))
						channel_match = 1;
				}
			}else{
				if(wpolicy_list[i].channel == channelieee_convert(0, ap->freq_band, ap->channel))
					channel_match = 1;
			}
		}

		if(!channel_match){
			continue;
		}else{
			//WIPSD_DEBUG("[%s:%d]: channel_match(%d)!\n", __FUNCTION__, __LINE__,wpolicy_list[i].channel);
		}

		if(strncmp(wpolicy_list[i].wnet, "any", 3) == 0){
			essid_match = 1;
		}else if(wpolicy_list[i].wnet[0] != '\0') {
			if(!ap){
				if(0 == get_wlist_node((char *)&sta->bssid[0], &ap)) {
					if(check_object_essid(wpolicy_list[i].wnet,ap))
						essid_match = 1;
				}
			}else{
				if(check_object_essid(wpolicy_list[i].wnet,ap))
					essid_match = 1;
			}
		}

		if(!essid_match){
			continue;
		}else{
			//WIPSD_DEBUG("[%s:%d]: wnet essid_match(%s)!\n", __FUNCTION__, __LINE__,wpolicy_list[i].wnet);
		}

		if(strncmp(wpolicy_list[i].ap_name, "any", 3) == 0){
			ap_match = 1;
		}else if(wpolicy_list[i].ap_mac[0] != '\0') {
			if(strncasecmp(wpolicy_list[i].ap_mac, bssid, 17) == 0)
				ap_match = 1;
		}else if(wpolicy_list[i].vendor[0] != '\0') {
			if(!ap){
				if(0 == get_wlist_node((char *)&sta->bssid[0], &ap)) {
					if(check_object_vendor(wpolicy_list[i].vendor,ap->vendor) > 0)
						ap_match = 1;
				}
			}else{
				if(check_object_vendor(wpolicy_list[i].vendor,ap->vendor) > 0)
					ap_match = 1;
			}
		}

		if(!ap_match){
			continue;
		}else{
			//WIPSD_DEBUG("[%s:%d]: ap_match(%s)!\n", __FUNCTION__, __LINE__,wpolicy_list[i].ap_name);
		}

		if(strncmp(wpolicy_list[i].sta_name, "any", 3) == 0) {
			sta_match = 1;
		}else if(wpolicy_list[i].sta_mac[0] != '\0' && wpolicy_list[i].sta_mac_mask[0] != '\0') {
			//WIPSD_DEBUG("[%s:%d]: sta_mac!\n", __FUNCTION__, __LINE__);
			mask = atoi(wpolicy_list[i].sta_mac_mask);

			if((mask == 48) && (strncasecmp(wpolicy_list[i].sta_mac, mac, 17)==0) ) {
				sta_match = 1;
			}
			else if(mask < 48 && mask > 0) {
				mask = mask/4;
				mask = mask + mask/2 - 1;

				if(mask > 0)
					if(strncasecmp(wpolicy_list[i].sta_mac, mac, mask)==0) {
						sta_match = 1;
					}
			}
		}else if(wpolicy_list[i].vendor[0] != '\0') {
			if(check_object_vendor(wpolicy_list[i].vendor,sta->vendor) > 0)
				sta_match = 1;
		}

		if(!sta_match){
			continue;
		}else{
			//WIPSD_DEBUG("[%s:%d]: sta_match(%s)!\n", __FUNCTION__, __LINE__,wpolicy_list[i].sta_name);
		}

		if(wpolicy_list[i].weid == WIPS_EID_MIN){		//全部事件
			wevent_match  = 1;
		}else {
			if(lookup_wevent_bitmap(wpolicy_list[i].weid, &sta->alert) == 1)	//lookup sta wevent
				wevent_match = 1;
			else {														//lookup ap wevent
				if(!ap){
					if(0 == get_wlist_node((char *)&sta->bssid[0], &ap)) {
						if(lookup_wevent_bitmap(wpolicy_list[i].weid, &ap->alert) == 1)
							wevent_match = 1;
					}
				}else{
					if(lookup_wevent_bitmap(wpolicy_list[i].weid, &ap->alert) == 1)
						wevent_match = 1;
				}
			}
		}

        nodeInfo * tmp=NULL;
        tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, (const char *)sta->bssid, 6);
        if (tmp && tmp->node_type & 0x80)
        {
            goto out;
        }

		if(!wevent_match){
			continue;
		}else{
			//WIPSD_DEBUG("[%s:%d]: wevent_match(%d)!\n", __FUNCTION__, __LINE__,wpolicy_list[i].weid);
		}

		if(strncmp(wpolicy_list[i].ctime, "any", 4) == 0){
			ctime_match = 1;
		}else if(wpolicy_list[i].ctime[0] != '\0') {
			if(check_object_ctime(wpolicy_list[i].ctime))
				ctime_match = 1;
		}

		if(!ctime_match){
			//WIPSD_DEBUG("[%s:%d]: ctime_match(%s)!\n", __FUNCTION__, __LINE__,wpolicy_list[i].ctime);
			continue;
		}


		if(essid_match && ap_match && sta_match && wevent_match && ctime_match && channel_match && sta->is_assoc2ap)
		{
			WIPSD_DEBUG("%s-%d:wpolicy(%d):weid:%d; wnet:%s; ap_name:%s; sta_name:%s; wevent:%s; ctime:%s; waction:%s; "
				"enable:%s; channel:%d; ap_mac:%s; sta_mac:%s.\n", __func__, __LINE__,
				wpolicy_list[i].wpid,wpolicy_list[i].weid,wpolicy_list[i].wnet,
				wpolicy_list[i].ap_name,wpolicy_list[i].sta_name,wpolicy_list[i].wevent,
				wpolicy_list[i].ctime,wpolicy_list[i].waction,wpolicy_list[i].enable,
				wpolicy_list[i].channel,wpolicy_list[i].ap_mac,
				wpolicy_list[i].sta_mac);

			if(strncmp(wpolicy_list[i].waction, "permit", 6) == 0) {
				goto out;
			}

			if(sta->block == 0 || sta->link_changed || (sta->block_func&0x1)==0x1 )
			{
                ret = blocked_bssid_with_sta(sta);
				if(ret > 0 
                    //&& memcmp(sta->sec_type, "open-system", 10)!=0 
                    //&& sta->sec_type[0]!='\x0'
                    )
				{
					memset((void *)&ipc_data, 0, sizeof(ipc_data));
					memcpy(ipc_data.mac, sta->mac, 6);
					memcpy(ipc_data.bssid, sta->bssid, 6);
					ipc_data.channel = sta->channel;
					ipc_data.freq_band = sta->freq_band;
					ipc_data.block_method = block_method;
					wipsd_block_by_lan(wpolicy_list[i].wpid, sta, NL_ADD_ADDR_OBJ);
					wipsd_block_by_wireless(&ipc_data, sta, WIPSD_ADD_BLOCK_INFO);
				}
                else
                    goto out;
				#if 0 //no use & mem leak

				if(!ap)
				{
					if(!get_wlist_node((char *)&sta->bssid[0], &ap))
					{
						__u32 datachannel = 0;
						if(sta->channel == ap->channel){
							datachannel = ap->channel;
						}else{
							WIPSD_DEBUG("sta-dch(%d)-ch(%d), ap-dch(%d)-ch(%d)\n",
								sta->data_channel, sta->channel, ap->data_channel, ap->channel);
						}
						strcpy(sta->sec_type, ap->sec_type);
						ret = add_block_node_by_blocklist(wpolicy_list[i].wpid, sta, sta->bssid, datachannel, ap->freq_band);
						if(ret < 0)
						{
							WIPSD_DEBUG("[%s:%d]: debug!\n", __FUNCTION__, __LINE__);
						}
					}
				}
				else
				{
					__u32 datachannel = 0;

					if(sta->channel == ap->channel){
						datachannel = ap->channel;
					}else{
						WIPSD_DEBUG("sta-dch(%d)-ch(%d), ap-dch(%d)-ch(%d)\n",
							sta->data_channel, sta->channel, ap->data_channel, ap->channel);
					}
					strcpy(sta->sec_type, ap->sec_type);
					sta->freq_band = ap->freq_band;
					sta->channel = datachannel;
					ret = add_block_node_by_blocklist(wpolicy_list[i].wpid, sta, sta->bssid, datachannel, ap->freq_band);
					if(ret < 0)
					{
						WIPSD_DEBUG("[%s:%d]: debug!\n", __FUNCTION__, __LINE__);
					}
				}
				#endif
				if(sta->block == 0) {
					sta->block = 1;
					//report_wips_event(sta, WIPS_EID_STA_BLOCK_START);
					sta->link_changed = 0;
				}

				if(ap){
					node_changed(ap, LIST_TASK_CREATE_FAKE_AP);
				}
			}
			else
			{
				memset((void *)&ipc_data, 0, sizeof(ipc_data));
				memcpy(ipc_data.mac, sta->mac, 6);
				memcpy(ipc_data.bssid, sta->bssid, 6);
				ipc_data.channel = sta->channel;
				ipc_data.freq_band = sta->freq_band;
				ipc_data.block_method = block_method;

				wipsd_block_by_lan(wpolicy_list[i].wpid, sta, NL_ADD_ADDR_OBJ);
				wipsd_block_by_wireless(&ipc_data, sta, WIPSD_ADD_BLOCK_INFO);
			}
            
            goto blocked_out;
		}
	}

out:
	if(sta)
	{
		block = sta->block;
		if(sta->block == 1)
		{
			report_wips_event(sta, WIPS_EID_STA_BLOCK_STOP);
			sta->block = 0;
            #if 1
			if(wpolicy_list && wpolicy_list[i].wpid)
			{
		   		del_block_node_by_blocklist(wpolicy_list[i].wpid, sta, sta->mac, ap?ap->bssid:NULL);
			}
			else
			{
				del_block_node_by_blocklist(0, sta, sta->mac, ap?ap->bssid:NULL);
			}
            #endif
            sta->block_func = 0;
			free_blocked_bssid(sta);
		}
	}
	return block;

blocked_out:
	if(sta)
	{
		sta->send_info_timeout = cur_time;
		block = sta->block;
        report_wips_event(sta, WIPS_EID_STA_BLOCK_START);
	}
	return block;
}

/*
void wpolicy_blocking_action(void)
{
	int ret,row,col;
	char query[512];
	char **dbResult;
	char *errmsg;

//WIPSD_DEBUG("begin wplicy_blocking_action\n");

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql_wconfig);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite wconfig.db error !");
		return;
	}

	//get wpolicy
	sprintf(query, "select * from wpolicy order by oid");
	ret = sqlite3_get_table( sql_wconfig, query, &dbResult, &row, &col, &errmsg);
	sqlite3_free_table(dbResult);

	if(row > 0) {

		ret = sqlite3_open("/usr/hls/log/log/beacon_test.db",&sql);
		if(ret != SQLITE_OK){
			WIPSD_DEBUG("open sqlite beacon_test.db error !");
			wipsd_sqlite3_close(sql_wconfig);
			return;
		}

		if(wpolicy_list != NULL) {
			wipsd_free(wpolicy_list);
			wpolicy_list = NULL;
		}

		wpolicy_num = row;
		wpolicy_list = calloc(row,sizeof(struct wpolicy_struct));
		if(!wpolicy_list) {
			wipsd_sqlite3_close(sql);
			wipsd_sqlite3_close(sql_wconfig);
			WIPSD_DEBUG("no memory!");
			return;
		}

		wpolicy_index = 0;
		sprintf(query,"select * from wpolicy order by oid");
		sqlite3_exec(sql_wconfig, query, get_wpolicy, NULL,NULL);

		ret = -sqlite3_get_table( sql, "select * from sta_list", &dbResult, &row, &col, &errmsg);
		sqlite3_free_table(dbResult);

		if(row > 0) {
			if(sta_list != NULL) {
				wipsd_free(sta_list);
				sta_list = NULL;
			}

			sta_num = row;
			sta_list = calloc(sta_num,sizeof(struct sta_node));

			if(!sta_list ) {
				wipsd_sqlite3_close(sql);
				wipsd_sqlite3_close(sql_wconfig);
				wipsd_free(wpolicy_list);
				wpolicy_list = NULL;
				return;
			}
//WIPSD_DEBUG("Debug: get sta data\n");
			sta_index = 0;
			ret = -sqlite3_exec(sql, "select * from sta_list", get_sta_data, NULL , NULL);

			// blocking sta
			do_wpolicy_action();
		} else
			sta_num = 0;

		wipsd_sqlite3_close(sql);
	}

	wipsd_sqlite3_close(sql_wconfig);
//WIPSD_DEBUG("end wplicy_blocking_action\n");
	return;
}

int do_blocking_action_by_channel(int ch)
{
	int s;
	char cmd[256];

	if(sta_list == NULL)
		return 0;

//WIPSD_DEBUG("begin:do_blocking_action_by_channel\n");

	for(s=0; s<sta_num; s++) {

		if(!sta_list[s].block ||
			sta_list[s].mac[0] == '\0' ||
			sta_list[s].bssid[0] == '\0' ||
			!isdigit(sta_list[s].channel[0]))
			continue;

		if( strncmp(reverse_sta_channel(ch), sta_list[s].channel, 4) != 0 )
			continue;

WIPSD_DEBUG("Debug:blocking sta:%s, ap:%s\n", sta_list[s].mac, sta_list[s].bssid);

		sprintf(cmd, "blocking %s sta %s %s %s %s", iface, sta_list[s].bssid, sta_list[s].mac,
			sta_list[s].bssid, "1");
		ret = system(cmd);
		sprintf(cmd, "blocking %s sta %s %s %s %s", iface, sta_list[s].mac, sta_list[s].bssid,
			sta_list[s].bssid, "1");
		ret = system(cmd);
	}

//WIPSD_DEBUG("end:do_blocking_action_by_channel\n");
	return 0;
}
*/
int sequence_num_hook(struct w_node * latest,struct w_node * exist)
{
	exist->sequence_num = exist->sequence_num + 0x10;
	latest->sequence_num = exist->sequence_num;
	return 0;
}
int get_arp_block_para_hook(struct w_node * latest,struct w_node * exist)
{
	memcpy(latest->addr_ipv4, exist->addr_ipv4, 4);
	memcpy(latest->gatemac, exist->gatemac, 6);
	memcpy(latest->bssid, exist->bssid, 6);
	memcpy(latest->sec_type, exist->sec_type, 10);
	/*    WIPSD_DEBUG("dev %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d)\n", latest->mac[0], latest->mac[1], latest->mac[2],
    latest->mac[3], latest->mac[4], latest->mac[5], latest->addr_ipv4[0], latest->addr_ipv4[1],latest->addr_ipv4[2], latest->addr_ipv4[3]);
    WIPSD_DEBUG("\tgate update %02x:%02x:%02x:%02x:%02x:%02x\n", latest->gatemac[0], latest->gatemac[1], latest->gatemac[2], latest->gatemac[3], latest->gatemac[4], latest->gatemac[5]);	*/
	return 0;
}

int do_blocking_list_by_channel(int index, int auxiliary_channel)
{
	//char cmd[256];
	block_sta_node *tmpnode;
	//int ret;
	struct w_node ww_node;

#if 0
	int block_num=0;
	if(0 == pthread_mutex_trylock(&block_table_1_lock)){
		tmpnode = block_table_1[index];
		block_num = 1;
	}else if(0 == pthread_mutex_trylock(&block_table_2_lock)){
		tmpnode = block_table_2[index];
		block_num = 2;
	}else{
		//usleep(50000);
		return -1;
	}
#else
	tmpnode = block_table[index];
#endif

	/*if(probe_enable)
		probe_request(&if_sendwlan,
						ww_node.bssid,
						ww_node.mac,
						ww_node.bssid,
						BLOCKING_FIXED_RATE,
						2000,
						0x1,
						block_method);*/

	while(tmpnode != NULL) {

		if(tmpnode->mac[0] == '\0' || tmpnode->bssid[0] == '\0'
			/*|| tmpnode->auxiliary_channel != auxiliary_channel*/) {
			tmpnode = tmpnode->next;
			continue;
		}

		if(index < 14 && index != get_block_index_2g(tmpnode->channel))
			continue;


#if 0
		sprintf(cmd, "/usr/hls/bin/blocking %s sta %s %s %s %s %d %d",
			iface,
			tmpnode->bssid,
			tmpnode->mac,
			tmpnode->bssid,
			"9",
			deau_seq,
			block_method);
		ret = system(cmd);
        deau_seq++;

#else
		str2mac(ww_node.mac,tmpnode->mac);
		str2mac(ww_node.bssid,tmpnode->bssid);
		switch(tmpnode->block_method){
			case 0x1:
				if(block_function&1){
				  if(deau_seq_en){
				    if(0 == find_wlistnode_sniffer(&ww_node, NO_ADD_NODE, sequence_num_hook)){
				      deau_seq = ww_node.sequence_num;
				    }else{
				      goto next;
				    }
				  }else{
					deau_seq = 72;
				  }
					deauth_blocking(&if_sendwlan,
							ww_node.bssid,
							ww_node.mac,
							ww_node.bssid,
									BLOCKING_FIXED_RATE,
							2000,/*deau_seq*/
									0x1,
									block_method);
					/*deauth_blocking(&if_sendwlan,
							ww_node.bssid,
							ww_node.mac,
							ww_node.bssid,
									BLOCKING_FIXED_RATE,
									2000,
									0x6,
									block_method);*/
					if(tmpnode->block_count++==0){
#ifdef DEBUG_WIPSD
					  WIPSD_DEBUG("deauth block %02x:%02x:%02x:%02x:%02x:%02x\n", ww_node.mac[0], ww_node.mac[1], ww_node.mac[2], ww_node.mac[3], ww_node.mac[4], ww_node.mac[5]);}
					//			WIPSD_DEBUG("( %02x:%02x:%02x:%02x:%02x:%02x )\n", ww_node.bssid[0], ww_node.bssid[1], ww_node.bssid[2], ww_node.bssid[3], ww_node.bssid[4], ww_node.bssid[5]);
#endif
				}
				break;
			case 0x2:
				if( block_function&(1<<1)){
					//cheat sta
					arp_attack_blocking(&if_sendwlan,
										ww_node.bssid,
										tmpnode->gate_mac,
										ww_node.mac,
										tmpnode->gate_ip,
										tmpnode->addr_ipv4,//not use
										0);
					if(tmpnode->block_count++==0){
#ifdef DEBUG_WIPSD
					  WIPSD_DEBUG("arp_block sta "NMACQUAD_FMT" (%d.%d.%d.%d)\n", NMACQUAD(ww_node.mac), tmpnode->gate_ip[0], tmpnode->gate_ip[1],tmpnode->gate_ip[2], tmpnode->gate_ip[3]);
#endif
					}
					/*arp_attack_blocking(&if_sendwlan,
										ww_node.bssid,
										memcmp(ww_node.gatemac, "\x00\x00\x00\x00\x00\x00", 6)==0 ? ww_node.bssid : ww_node.gatemac,
										"\xff\xff\xff\xff\xff\xff",
										wgate_ip,
										ww_node.addr_ipv4,//not use
										0);*/
					//cheat wgate
					arp_attack_blocking(&if_sendwlan,
									ww_node.bssid,
									ww_node.mac,
									tmpnode->gate_mac,
									tmpnode->addr_ipv4,
									tmpnode->gate_ip,//not use
									1);

					//				WIPSD_DEBUG("arp_block %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d)\n", ww_node.mac[0], ww_node.mac[1], ww_node.mac[2],
					//ww_node.mac[3], ww_node.mac[4], ww_node.mac[5], ww_node.addr_ipv4[0], ww_node.addr_ipv4[1],ww_node.addr_ipv4[2], ww_node.addr_ipv4[3]);
				}
				break;
		}
		blocked_node_numb++;
#endif
next:
		tmpnode = tmpnode->next;
	}

#if 0
	if(block_num == 1){
		pthread_mutex_unlock(&block_table_1_lock);
	}else if(block_num == 2){
		pthread_mutex_unlock(&block_table_2_lock);
	}else{
	}
#else
#endif
	return 0;
}

int do_blocking_list(int freq, int ch)
{
	int index;

	if(freq == 5) {
		index = get_block_index_5g(ch);
		do_blocking_list_by_channel(index, MASTER_CHANNEL);
		return 0;
	} else {
		index = get_block_index_2g(ch);
		do_blocking_list_by_channel(index, MASTER_CHANNEL);
		return 0;

/*		if( !multi_channel_block) {
			do_blocking_list_by_channel(index, MASTER_CHANNEL);
			return 0;
		} else {
		   	switch (index) {		//not channel, only list index!
				case 0:
					do_blocking_list_by_channel(0, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(1, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(2, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(3, AUXILIARY_CHANNEL);
					return 0;
				case 1:
					if(cc & (1 << 0))do_blocking_list_by_channel(0, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(1, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(2, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(3, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(4, AUXILIARY_CHANNEL);
					return 0;
				case 2:
					if(cc & (1 << 1))do_blocking_list_by_channel(0, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(1, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(2, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(3, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(4, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(5, AUXILIARY_CHANNEL);
					return 0;
				case 3:
					if(cc & (1 << 2))do_blocking_list_by_channel(0, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(1, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(2, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(3, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(4, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(5, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(6, AUXILIARY_CHANNEL);
					return 0;
				case 4:
					if(cc & (1 << 2))do_blocking_list_by_channel(1, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(2, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(3, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(4, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(5, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(6, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(7, AUXILIARY_CHANNEL);
					return 0;
				case 5:
					if(cc & (1 << 2))do_blocking_list_by_channel(2, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(3, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(4, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(5, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(6, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(7, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(8, AUXILIARY_CHANNEL);
					return 0;
				case 6:
					if(cc & (1 << 2))do_blocking_list_by_channel(3, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(4, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(5, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(6, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(7, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(8, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(9, AUXILIARY_CHANNEL);
					return 0;
				case 7:
					if(cc & (1 << 2))do_blocking_list_by_channel(4, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(5, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(6, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(7, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(8, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(9, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(10, AUXILIARY_CHANNEL);
					return 0;
				case 8:
					if(cc & (1 << 2))do_blocking_list_by_channel(5, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(6, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(7, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(8, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(9, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(10, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(11, AUXILIARY_CHANNEL);
					return 0;
				case 9:
					if(cc & (1 << 2))do_blocking_list_by_channel(6, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(7, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(8, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(9, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(10, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(11, AUXILIARY_CHANNEL);
					if(cc & (1 << 2))do_blocking_list_by_channel(12, AUXILIARY_CHANNEL);
					return 0;
				case 10:
					if(cc & (1 << 2))do_blocking_list_by_channel(7, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(8, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(9, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(10, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(11, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(12, AUXILIARY_CHANNEL);
					return 0;
				case 11:
					if(cc & (1 << 2))do_blocking_list_by_channel(8, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(9, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(10, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(11, MASTER_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(12, AUXILIARY_CHANNEL);
					return 0;
				case 12:
					if(cc & (1 << 2))do_blocking_list_by_channel(9, AUXILIARY_CHANNEL);
					if(cc & (1 << 1))do_blocking_list_by_channel(10, AUXILIARY_CHANNEL);
					if(cc & (1 << 0))do_blocking_list_by_channel(11, AUXILIARY_CHANNEL);
					do_blocking_list_by_channel(12, MASTER_CHANNEL);
					return 0;
				case 13:
					do_blocking_list_by_channel(13, MASTER_CHANNEL);
					return 0;

				default:
					return 0;
			}
		}*/
	}
}

int read_wireless_config(void* data, int n_columns, char** column_values, char** column_names)
{

	if(column_values[0])
		wireless_enable = atoi(column_values[0]);
	if(wireless_enable < 0 || wireless_enable > 1)
		wireless_enable = 1;

	if(column_values[1])
		wips_enbale = atoi(column_values[1]);
	if(wips_enbale < 0 || wips_enbale > 1)
		wips_enbale = 1;

	if(column_values[2])
		monitor_band = atoi(column_values[2]);
	if(monitor_band != 2 && monitor_band != 5 && monitor_band != 25)
		monitor_band = 2;

	if(column_values[3])
		channel_gap = atoi(column_values[3]);
	if(channel_gap < 10 || channel_gap > 999)
		channel_gap = 50;

	if(column_values[4]) {
		monitor_alert = atoi(column_values[4]);
	}
	if(monitor_alert != 0 && monitor_alert != 1 && monitor_alert != 2)
		monitor_alert = 0;

	if(column_values[5])
		block_method = atoi(column_values[5]);
	if(block_method != 3 && block_method != 4 && block_method != 1 && block_method != 2)
		block_method = 1;

	if(column_values[6])
		wireless_node_age = atoi(column_values[6]);
	if(wireless_node_age < 100 || wireless_node_age > 999)
		wireless_node_age = 900;

	if(column_values[7])
		lan_mon_enable = atoi(column_values[7]);
	if(lan_mon_enable < 0 || lan_mon_enable > 1)
		lan_mon_enable = 0;

	if(column_values[8])
		strncpy(lan_mon_if, column_values[8], 128);

	if(column_values[9])
		strncpy(lan_mon_net, column_values[9], 128);

	if(column_values[10])
		lan_mon_gap = atoi(column_values[10]);
	if(lan_mon_gap < 1 || lan_mon_gap > 99)
		lan_mon_gap = 5;

	if(column_values[11])
		wips_sensitivity = atoi(column_values[11]);
	if(wips_sensitivity < -99 || wips_sensitivity > -10)
		wips_sensitivity = -96;

	if(column_values[12])
		multi_channel_block = atoi(column_values[12]);
	if(multi_channel_block < 0 || multi_channel_block > 1)
		multi_channel_block = 0;

#if 0
	printf("wireless_enable:%d.\n",wireless_enable);
	printf("wips_enbale:%d.\n",wips_enbale);
	printf("monitor_band:%d.\n",monitor_band);
	printf("channel_gap:%d.\n",channel_gap);
	printf("monitor_alert:%d.\n",monitor_alert);
	printf("block_method:%d.\n",block_method);
	printf("wireless_node_age:%d.\n",wireless_node_age);
	printf("lan_mon_gap:%d.\n",lan_mon_gap);
	printf("wips_sensitivity:%d.\n",wips_sensitivity);
	printf("multi_channel_block:%d.\n",multi_channel_block);
#endif

	return 0;
}

int get_wireless_config(void)
{
	sqlite3 *sql = NULL;
	int ret;

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite wconfig.db error !");
		return -1;
	}

	ret = -sqlite3_exec(sql, "select * from wpara", read_wireless_config, NULL,NULL);

    if(sql)
    	wipsd_sqlite3_close(sql);
	return ret;
}

void *lan_mon_thread(void *p)
{
	do_active_lan_mon_period();

	return NULL;
}
#if 0
void updata_block_list_node(void)
{
	struct list_tast *mp;
	int times = 0;
again:
	if(block_tast_head == NULL && block_tast_rear == NULL){
		return;
	}
	else{
		if(block_tast_head->next == NULL){
			mp = block_tast_head;
			block_tast_head = NULL;
			block_tast_rear = NULL;
		}else{
			mp = block_tast_head;
			block_tast_head = mp->next;
		}
	}

	switch(mp->task_type){
		case BLOCK_TASK_ADD_NODE:
			{
			nodeInfo_2beBlock *tmp = (nodeInfo_2beBlock *)mp->node;
			if(tmp && tmp->block_method==0x1){
				char mac[24];
				char bssid[24];
				sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", tmp->mac[0], tmp->mac[1], tmp->mac[2], tmp->mac[3], tmp->mac[4], tmp->mac[5]);
				sprintf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x", tmp->bssid[0], tmp->bssid[1], tmp->bssid[2],
					tmp->bssid[3], tmp->bssid[4], tmp->bssid[5]);
				add_block_node(NULL, mac, bssid, tmp->channel, tmp->freq_band,tmp->ipv4);
			}else if(tmp && tmp->block_method==0x2){
				add_arpblock_node(tmp);
			}
			wipsd_free(tmp);
			}
			break;
		case BLOCK_TASK_DEL_NODE:
			{
			nodeInfo_2beBlock *tmp = (nodeInfo_2beBlock *)mp->node;
			if(tmp){
				char mac[24];
				sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", tmp->mac[0], tmp->mac[1], tmp->mac[2], tmp->mac[3], tmp->mac[4], tmp->mac[5]);
				del_block_node(NULL, mac, "Any");
			}
			wipsd_free(tmp);
			}
			break;
		default :
			WIPSD_DEBUG("unknown block_task type!\n");
			break;
	}
	wipsd_free(mp);

	if(times++ < 100)
		goto again;
}
#endif
char *prepare_log_data_test(IN struct w_node *ap_val, IN int event, int pri)
{
	return "aaaa";
}

char *prepare_log_data(IN struct w_node *ap_val, IN int event, int pri)
{
	char  tmp[32];
	char tmp1[64];
	//time_t ltime;
	struct tm *gentime;
	struct log_buf lbuf;
	//char dev_ipaddr[64];
	//char dev_mac[24];


	log_buf_init(&lbuf);
#if 0
	log_snprintf(&lbuf,  kw[WIPS_SERIALNUM].maxsize + MAX_PRE_STRING,  FMT(kw[WIPS_SERIALNUM].kw_type),\
				kw[WIPS_SERIALNUM].name, &serno_info.serno);
#endif
#if 0
	/*gentime && EVECOUT*/
	bzero(&tmp1, 0);
	time(&ltime);
	gentime = localtime(&ltime);
	snprintf(tmp1,64,"\"%d-%02d-%02d %02d:%02d:%02d\"",\
		gentime->tm_year + 1900, gentime->tm_mon+1, gentime->tm_mday, \
		gentime->tm_hour, gentime->tm_min, gentime->tm_sec);
	log_snprintf(&lbuf, kw[WIPS_GENTIME].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_GENTIME].kw_type), \
				kw[WIPS_GENTIME].name, (char *)tmp1);
#endif
	/*wipsip & wipsmac*/
	//memset(&dev_ipaddr, 0 ,sizeof(dev_ipaddr));
	//memset(&dev_mac, 0, sizeof(dev_mac));
	//lfd_get_dev_para(GET_DEV_ETH0_IP, (char *)&dev_ipaddr);
	//lfd_get_dev_para(GET_DEV_ETH0_MAC, (char *)&dev_mac);

#if 0
	pthread_mutex_lock(&dev_lock);
	log_snprintf(&lbuf, kw[WIPS_IP].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_IP].kw_type), \
			kw[WIPS_IP].name, &dev_ipaddr);
	log_snprintf(&lbuf, kw[WIPS_MAC].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_MAC].kw_type), \
			kw[WIPS_MAC].name, &dev_mac);
	pthread_mutex_unlock(&dev_lock);
#endif
	/*ssid & bssid &*/
	bzero(&tmp,0);
	sprintf((char *)&tmp, NMACQUAD_FMT, NMACQUAD(ap_val->bssid));
	log_snprintf(&lbuf, kw[WE_BSSID].maxsize + MAX_PRE_STRING, FMT(kw[WE_BSSID].kw_type), \
			kw[WE_BSSID].name, &tmp);

	log_snprintf(&lbuf, kw[WE_SSID].maxsize + MAX_PRE_STRING, FMT(kw[WE_SSID].kw_type), \
			kw[WE_SSID].name, ap_val->ssid);

	/*mac & wmac*/
	bzero(&tmp,0);
	sprintf((char *)&tmp, NMACQUAD_FMT,NMACQUAD(ap_val->lan_mac));
	log_snprintf(&lbuf, kw[WE_MAC].maxsize + MAX_PRE_STRING, FMT(kw[WE_MAC].kw_type),  \
			kw[WE_MAC].name, &tmp);

	bzero(&tmp,0);
	sprintf((char *)&tmp, NMACQUAD_FMT, NMACQUAD(ap_val->mac));
	log_snprintf(&lbuf, kw[WE_WMAC].maxsize + MAX_PRE_STRING, FMT(kw[WE_WMAC].kw_type), \
			kw[WE_WMAC].name, &tmp);

#if 0
	/*protocol & devtype*/
	log_snprintf(&lbuf, kw[WE_PROTOCOL].maxsize + MAX_PRE_STRING, FMT(kw[WE_PROTOCOL].kw_type), \
			kw[WE_PROTOCOL].name,"");
#endif

	bzero(&tmp, 0);
	if(ap_val->node_type & AP)
		sprintf((char *)&tmp, "ap");
	else if(ap_val->node_type & STA)
		sprintf((char *)&tmp, "station");
	log_snprintf(&lbuf, kw[WE_DEV_TYPE].maxsize + MAX_PRE_STRING, FMT(kw[WE_DEV_TYPE].kw_type), \
			kw[WE_DEV_TYPE].name,"ap");

	/*security & channel*/
	log_snprintf(&lbuf, kw[WE_SECURITY].maxsize + MAX_PRE_STRING, FMT(kw[WE_SECURITY].kw_type), \
			kw[WE_SECURITY].name, ap_val->sec_type);
	log_snprintf(&lbuf, kw[WE_CHANNEL].maxsize + MAX_PRE_STRING, FMT(kw[WE_CHANNEL].kw_type), \
			kw[WE_CHANNEL].name, ap_val->channel);
#if 0
	/*signal & noise & rates & ipaddr*/
	log_snprintf(&lbuf, kw[WE_SIGNAL].maxsize + MAX_PRE_STRING, "%s=%d ", \
			kw[WE_SIGNAL].name, ap_val->signal);
	log_snprintf(&lbuf, kw[WE_NOISE].maxsize + MAX_PRE_STRING ,"%s=%d ", \
			kw[WE_NOISE].name, ap_val->noise);
	log_snprintf(&lbuf, kw[WE_RATES].maxsize + MAX_PRE_STRING, "%s=%d ", \
			kw[WE_RATES].name, ap_val->rates);
	log_snprintf(&lbuf, kw[WE_IPADDR].maxsize + MAX_PRE_STRING, FMT(kw[WE_IPADDR].kw_type), \
			kw[WE_IPADDR].name, ap_val->ipv4);
#endif

	/*vendor */
	char vendor[128];
	memset(&vendor, 0, sizeof(vendor));
	snprintf((char *)&vendor,sizeof(vendor), "\"%s\"", ap_val->vendor);
	log_snprintf(&lbuf, kw[WE_VENDOR].maxsize + MAX_PRE_STRING, FMT(kw[WE_VENDOR].kw_type), \
			kw[WE_VENDOR].name, vendor);

	/* uptime & lasttime */
	bzero(&tmp1, 0);
	gentime = localtime(&ap_val->up_time);
	snprintf((char *)&tmp1, sizeof(tmp1), "\"%d-%02d-%02d %02d:%02d:%02d\"",\
		gentime->tm_year + 1900, gentime->tm_mon+1, gentime->tm_mday, \
		gentime->tm_hour, gentime->tm_min, gentime->tm_sec);
	log_snprintf(&lbuf, kw[WE_UP_TIME].maxsize + MAX_PRE_STRING, FMT(kw[WE_UP_TIME].kw_type), \
			kw[WE_UP_TIME].name, &tmp1);

	bzero(&tmp1, 0);
	gentime = localtime(&ap_val->last_time);
	snprintf((char *)tmp1,sizeof(tmp1),"\"%d-%02d-%02d %02d:%02d:%02d\"",\
		gentime->tm_year + 1900, gentime->tm_mon+1, gentime->tm_mday, \
		gentime->tm_hour, gentime->tm_min, gentime->tm_sec);
	log_snprintf(&lbuf, kw[WE_LAST_TIME].maxsize + MAX_PRE_STRING, FMT(kw[WE_LAST_TIME].kw_type), \
		kw[WE_LAST_TIME].name, &tmp1);

	/*grpname*/
	if(event < WIPS_EID_MAX){
		int grp_id = wevent_list[event -1].grp_id;
		int i;
		for(i = WIPS_EID_ALL; i<WIPS_EID_MAX ; i++){
			if(grp_id == wevent_list[i].id)
				break;
		}
		log_snprintf(&lbuf, kw[WE_GRP_NAME].maxsize + MAX_PRE_STRING, FMT(kw[WE_GRP_NAME].kw_type), \
				kw[WE_GRP_NAME].name, P(wevent_list[i].name));
	}else if(event == WIPS_EID_SIGNAL_TOOLOW)
				log_snprintf(&lbuf, kw[WE_GRP_NAME].maxsize + MAX_PRE_STRING, FMT(kw[WE_GRP_NAME].kw_type), \
				kw[WE_GRP_NAME].name, "信号太低");
	else if(event > WIPS_EID_MAX && event != WIPS_EID_SIGNAL_TOOLOW)
				log_snprintf(&lbuf, kw[WE_GRP_NAME].maxsize + MAX_PRE_STRING, FMT(kw[WE_GRP_NAME].kw_type), \
				kw[WE_GRP_NAME].name, P(eve_pri_table[WIPS_EID_ACTION_GRP-1].name));


	/*eventname*/
	if(event < WIPS_EID_MAX)
		log_snprintf(&lbuf, kw[WE_EVENT_NAME].maxsize + MAX_PRE_STRING, FMT(kw[WE_EVENT_NAME].kw_type), \
				kw[WE_EVENT_NAME].name, P(wevent_list[event -1].name));
	else if(event > WIPS_EID_MAX)
		log_snprintf(&lbuf, kw[WE_EVENT_NAME].maxsize + MAX_PRE_STRING, FMT(kw[WE_EVENT_NAME].kw_type), \
				kw[WE_EVENT_NAME].name, P(eve_pri_table[event -1].name));
	/*blkflag*/
	log_snprintf(&lbuf, kw[WE_BLK_FLG].maxsize + MAX_PRE_STRING, FMT(kw[WE_BLK_FLG].kw_type), \
			kw[WE_BLK_FLG].name, ap_val->block);
	/*pri*/
	log_snprintf(&lbuf, kw[WE_PRI].maxsize + MAX_PRE_STRING, FMT(kw[WE_PRI].kw_type), \
			kw[WE_PRI].name, pri);
	log_snprintf(&lbuf, kw[WIPS_EVECOUNT].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_EVECOUNT].kw_type), \
				kw[WIPS_EVECOUNT].name, 1);
	/*eventid*/
	log_snprintf(&lbuf, kw[WIPS_EVEID].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_EVEID].kw_type), \
				kw[WIPS_EVEID].name, event);
	if(event < WIPS_EID_MAX)
		log_snprintf(&lbuf, kw[WIPS_EVECONTENT].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_EVECONTENT].kw_type), \
					kw[WIPS_EVECONTENT].name, dic_table[event -1]);
	else if(event > WIPS_EID_MAX)
		log_snprintf(&lbuf, kw[WIPS_EVECONTENT].maxsize + MAX_PRE_STRING, FMT(kw[WIPS_EVECONTENT].kw_type), \
					kw[WIPS_EVECONTENT].name, P(eve_pri_table[event -1].meaning));
	/*WEObjName*/
		log_snprintf(&lbuf, kw[WE_OBJ_NAME].maxsize + MAX_PRE_STRING, FMT(kw[WE_OBJ_NAME].kw_type), \
			kw[WE_OBJ_NAME].name, ap_val->name);

	return lbuf.buf;

}

int report_wips_ap_event(struct w_node *ap_val, int event)
{
	if(!wips_enbale)		//wips disable
		return 0;

	if(event > WIPS_EID_AP_BLOCK_STOP || event < WIPS_EID_MIN)
		return 0;

	if(event < WIPS_EID_MAX){
		if(test_wevent_bitmap(event, &ap_val->alert) != 0) {
			return 0;	// have this event , don't report
		}
	}
	print_event_info(event, ap_val);

	if((ap_val->node_type & 0x01) != 0x01) {
		WIPSD_DEBUG("report_wips_ap_event:%d, is not ap node!\n",event);
		return 0;
	}

	if(event < WIPS_EID_MAX)
		/*ap_val->alert =*/ set_wevent_bitmap(event, &ap_val->alert);


	if(monitor_alert == 1) {
		if(ap_val->ipv4[0] == '\0')//if(find_lan_ip(mac) == NULL)
			return 0;
	}
	else if(monitor_alert == 2) {
		if(ap_val->ipv4[0] != '\0')//if(find_lan_ip(mac) != NULL)
			return 0;
	}

#ifdef MEMLOG
	return log_event_memlog(ap_val, event, log_mode);
#else
	return log_event_sqllog(ap_val, event, log_mode);
#endif
}


int report_wips_sta_event(struct w_node *sta_val, int event)
{
	if(!wips_enbale)		//wips disable
		return 0;
	if(event >WIPS_EID_AP_BLOCK_STOP || event < WIPS_EID_MIN)
		return 0;

	if(event < WIPS_EID_MAX){
		if(test_wevent_bitmap(event, &sta_val->alert) != 0) {
			return 0;	// have this event , don't report
		}
	}
	print_event_info(event, sta_val);

	if(event < WIPS_EID_MAX)
		/*sta_val->alert =*/ set_wevent_bitmap(event, &sta_val->alert);

	if(!(sta_val->node_type & 0x06)) {
		char mac[24];
		sprintf(mac, NMACQUAD_FMT,NMACQUAD(sta_val->mac));
		WIPSD_DEBUG("report_wips_sta_event:%d, is not station node[%02X] [%s]!\n",
			event, sta_val->node_type, mac);

		return 0;
	}
	if(monitor_alert == 1) {
		if(sta_val->ipv4[0] == '\0')//if(find_lan_ip(mac) == NULL)
			return 0;
	}
	else if(monitor_alert == 2) {
		if(sta_val->ipv4[0] != '\0')//if(find_lan_ip(mac) != NULL)
			return 0;
	}
#ifdef MEMLOG
	return log_event_memlog(sta_val, event, log_mode);
#else
	return log_event_sqllog(sta_val, event, log_mode);
#endif
}

int report_wips_event(struct w_node *node, int event)
{
#if 0
	if(/* 短时间内重启 &&*/ fresh_time < 10 && event > WIPS_EID_ASSO_DENIED_STA){
		/* ->alert =*/ set_wevent_bitmap(event, &node->alert);
		return 0;
	}
#endif
	if((node->node_type & 0x01) == 0x01) {
		report_wips_ap_event(node, event);
	}

	if(node->node_type & 0x06) {
		report_wips_sta_event(node, event);
	}

	return 0;
}

int clear_wips_event(struct w_node *node, int event)
{
	if(event >= WIPS_EID_MAX || event < WIPS_EID_MIN)
		return -1;

	if(test_wevent_bitmap(event, &node->alert) == 0) {
		return -1;	//
	}

	/*node->alert = */clear_wevent_bitmap(event, &node->alert);

	return 0;
}

int event_count(int * count,int c_max, int * interval, int inter_max)
{
	int state=0;

	if( fresh_time < *interval + inter_max){
		*count += 1;
	}else{
		*count += 1;
		if( *count >= c_max){
			state = 1;
		}
		*count = 0;
		*interval = fresh_time;
	}
#if 0
	WIPSD_DEBUG("count = %d\n",*count);
	WIPSD_DEBUG("c_max = %d\n",c_max);
	WIPSD_DEBUG("interval = %d\n",*interval);
	WIPSD_DEBUG("inter_max = %d\n",inter_max);
	WIPSD_DEBUG("fresh_time = %d\n",fresh_time);
	WIPSD_DEBUG("state = %d\n",state);
#endif
	return state;
}

int add_internal_ssid2list(char * ssid)
{
	struct list_tast *mp=NULL;
	char * ssidbuf=NULL;

	if(!ssid) return -1;

	ssidbuf = XMALLOC(MTYPE_WIPS_DEBUG_SSID_BUF,SSID_BUFSIZE_D);
	mp =  XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
	if(mp == NULL || ssidbuf == NULL){
		WIPSD_DEBUG("malloc for new add_internal_ssid2list err!\n");
		XFREE(MTYPE_WIPS_DEBUG_MP_NODE,mp);
		XFREE(MTYPE_WIPS_DEBUG_SSID_BUF,ssidbuf);
		return -1;
	}
	memset(mp,0,sizeof(struct list_tast));
	memcpy(ssidbuf, ssid, SSID_BUFSIZE_D);
	mp->node = (void *)ssidbuf;
	mp->task_type= LIST_TASK_ADDSSID;
	insertListTask(mp);
	//WIPSD_DEBUG("add_internal_ssid2list ssid= %s\n",ssid);
	return 0;
}

#define SEND_MAX_LEN 30720
void wipsd_cmd_send(ListBuf *treebuf, int cfd)
{
	char com_send, com_recv[20], i, *send_bufname;
	int ret, last_data, len2send;

	int tmp_index = cfd;
	if(cfd < 1 || cfd >= FD_MAX) return;
	cfd = fd_CMD[cfd];
	if(cfd <= 0) return;

	memcpy(com_recv,"send_start", 10);
	len2send = treebuf->len + sizeof(int);
	com_send = len2send / SEND_MAX_LEN ;
	last_data = len2send % SEND_MAX_LEN;
	if( last_data > 0) com_send++;
	com_recv[10] = com_send;
	for(i=0;i<=com_send;i++){
		if(i>0){
			send_bufname = (char *)(treebuf) + (i-1)*SEND_MAX_LEN;
			if(i == com_send && last_data >0){
				if((ret = write(cfd, send_bufname, last_data)) !=last_data){
//					perror("Fail to write a001");
					ret = write(cfd, "send_err", 8);
					break;
				}
			}else{
				if( (ret = write(cfd, send_bufname, SEND_MAX_LEN)) !=SEND_MAX_LEN){
//					perror("Fail to write a002");
					ret = write(cfd, "send_err", 8);
					break;
				}else{
					memset(com_recv,0,20);
				}
			}
		}else{
			if((ret = write(cfd, com_recv, 11)) !=11){
//				perror("Fail to write a003");
				ret = write(cfd, "send_err", 8);
				break;
			}
		}
		if((ret = read(cfd,com_recv,20))==-1){
//			perror("Fail to read a001");
			ret = write(cfd, "send_err", 8);
			break;
		}else if(memcmp( com_recv,"ACK",3) != 0){
//			WIPSD_DEBUG("read a002 incorrect [%s]\n", com_recv);
			ret = write(cfd, "send_err", 8);
			break;
		}
	}
	close(cfd);
	fd_CMD[tmp_index] = 0;
}
/*=============== ph =================*/

struct list_tast *list_tast_head = NULL;
struct list_tast *list_tast_rear = NULL;
int list_task_tmp = 255;
#if 0
void *list_task(void *p)
{
	for(;;){
		if(re_create_recv_socket == RE_CREATE_RECV_SOCKET){
			sleep(5);
			if(if_wlan.fd > 0){
				WIPSD_DEBUG("close if_wlan.fd[%ld] for RE_CREATE_RECV_SOCKET\n", if_wlan.fd);
				close(if_wlan.fd);
				if_wlan.fd = 0;
			}
			if(if_sendwlan.fd> 0){
				WIPSD_DEBUG("close if_sendwlan.fd[%ld] for RE_CREATE_RECV_SOCKET\n", if_sendwlan.fd);
				close(if_sendwlan.fd);
				if_sendwlan.fd = 0;
			}
			pre_init_interface(iface);
			iface_socket_init(&if_wlan, iface);
			iface_socket_init(&if_sendwlan, iface);
			auto_operating_fakeap(NULL, 1);
			re_create_recv_socket = 0;
		}
		sniffer(&if_wlan);
	}

	return NULL;
}
#endif

int ussleep(long us)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = us;

	return select(0, NULL, NULL, NULL, &tv);

}

void task_stack(void)
{
	struct list_tast *mp;
//	int cfd = 0;
	static ListBuf *treebuf =NULL;
//	struct w_node *tmp_wnode =NULL;

	if(!treebuf){
#ifdef MIPS
		treebuf = XMALLOC(MTYPE_WIPS_DEBUG_TREE_NODE,sizeof(int)+sizeof(struct event_memlog_pkt)*EVENT_MEM_LOGGER_BUFFERSIZE+MAX_SHARE_PKT_SIZE);
#else
		treebuf =  XMALLOC(MTYPE_WIPS_DEBUG_TREE_NODE,sizeof(ListBuf));
#endif
		if(!treebuf){
			WIPSD_DEBUG("list_task malloc treebuf err!\n");
			return;
		}
	}

	if(list_tast_head == NULL && list_tast_rear == NULL){
		ussleep(600);
		return;
	}
	if(cmd_highest_priority > 0){
		struct list_tast *last;
		struct list_tast *tmp;
		last = tmp = list_tast_head;
		for(;;){
			if(!tmp){
				cmd_highest_priority = 0;
				goto general;
			}

			switch(tmp->task_type){
				case LIST_TASK_GETAPWLIST:
				case LIST_TASK_GETSTAWLIST:
				case LIST_TASK_GETWNODE:
					if(tmp == list_tast_head){
						cmd_highest_priority--;
						goto general;
					}else if(tmp == list_tast_rear && last != NULL){
						mp = tmp;
						list_tast_rear = last;
						last->next = NULL;
						cmd_highest_priority = 0;
					}else{
						cmd_highest_priority--;
						last->next = tmp->next;
						mp = tmp;
					}
					goto out_for;
					break;

				default :
					last = tmp;
					tmp = tmp->next;
					break;

				}
		}
	}
	else{
general:
		if(list_tast_head->next == NULL){
			mp = list_tast_head;
			list_tast_head = NULL;
			list_tast_rear = NULL;
		}else{
			mp = list_tast_head;
			list_tast_head = mp->next;
		}
	}

out_for:
	//WIPSD_DEBUG("list_task type:%d\n", mp->task_type);
	list_task_tmp = mp->task_type;
	listask_polln++;
	switch(mp->task_type){
		case LIST_TASK_ADD2APLIST:{
			//WIPSD_DEBUG("LIST_TASK_ADD2APLIST\n");

			w_node_list *tmp;
			tmp = (w_node_list *)mp->node;
			check_stalist(&sta_list_p, &sta_list_tail,&tmp->b_frame);
			add_wlistnode((w_node_list *)mp->node, &beacon_list_p, &beacon_list_tail);}
			break;
		case LIST_TASK_ADD2STALIST:{
			//WIPSD_DEBUG("LIST_TASK_ADD2STALIST\n");

			w_node_list *tmp;
			tmp = (w_node_list *)mp->node;
			check_stalist(&beacon_list_p, &beacon_list_tail,&tmp->b_frame);
			add_wlistnode((w_node_list *)mp->node, &sta_list_p, &sta_list_tail);}
			break;
		case LIST_TASK_CHECKWLIST:
			check_adhoc_ap_ssid(NULL, 1);
			debug_sta_number = check_wlist(&sta_list_p, &sta_list_tail,NULL);
			check_apnumber_eachchannel(0, 1);
			check_ap_essid_seting(NULL, 1);
			debug_ap_number	= check_wlist(&beacon_list_p, &beacon_list_tail,NULL);
			break;
#if 0
		case LIST_TASK_GETAPWLIST:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				debug_ap_number	=check_wlist(&beacon_list_p, &beacon_list_tail,treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;
case LIST_TASK_GETSTAWLIST:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				debug_sta_number	=check_wlist(&sta_list_p, &sta_list_tail,treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;
		case LIST_TASK_GETWNODE:
			tmp_wnode = (struct w_node *)mp->node;
			cfd = tmp_wnode->noise;
			if(cfd > 0){
				struct w_node * nd = NULL;
				treebuf->len =0;
				if(0 == get_wlist_node((char *)tmp_wnode->mac, &nd)){
					memcpy(treebuf->buf, nd, sizeof(struct w_node));
					treebuf->len = sizeof(struct w_node);
					wipsd_cmd_send(treebuf, cfd);
				}else{
					if(cfd >= 1 && cfd < FD_MAX){
						if(fd_CMD[cfd] > 0){
							close(fd_CMD[cfd]);
							fd_CMD[cfd] = 0;
						}
					}
				}
			}
			wipsd_free(mp->node);
			break;
#endif

		case LIST_TASK_UPDATE_WPOLICY:
			update_sta_waction(&sta_list_p, &sta_list_tail, NULL);
			break;
		case LIST_TASK_APSTA:
			check_stalist(&sta_list_p, &sta_list_tail,(struct w_node *)mp->node);
			break;

		case LIST_TASK_ADDSSID:
			add_internal_ssid((char * )mp->node, &internal_ssid);
			break;
#if 0
		case LIST_TASK_TREE_AP_SSID_CHANGE:
			tree_ap_ssid_change((struct w_node * )mp->node);
			XFREE(MTYPE_WIPS_DEBUG_WNODE_CHANGE,mp->node);
			break;

		case LIST_TASK_TREE_AP_CHANNEL_CHANGE:
			tree_ap_channel_change((struct w_node * )mp->node);
			wipsd_free(mp->node);
			break;

		case LIST_TASK_TREE_STA_BSSID_CHANGE:
			tree_sta_bssid_change((struct w_node * )mp->node);
			XFREE(MTYPE_WIPS_DEBUG_WNODE_CHANGE,mp->node);
			break;

		case LIST_TASK_TREE_STA_CHANNEL_CHANGE:
			tree_sta_channel_change((struct w_node * )mp->node);
			wipsd_free(mp->node);
			break;
		case LIST_TASK_TREE_GET_ESSID_NAME_ID:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				tree_get_essid_name_id(treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;

		case LIST_TASK_TREE_GET_BY_ESSID_ID:
			tmp_wnode = (struct w_node *)mp->node;
			cfd = tmp_wnode->refresh_time;
			if(cfd > 0){
				treebuf->len =0;
				tree_get_by_essid_id(treebuf, tmp_wnode);
				wipsd_cmd_send(treebuf, cfd);
			}
			wipsd_free(mp->node);
			break;


		case LIST_TASK_TREE_GET_BY_A_ESSID:
			tmp_wnode = (struct w_node *)mp->node;
			cfd = tmp_wnode->refresh_time;
			if(cfd > 0){
				treebuf->len =0;
				tree_get_by_a_essid(treebuf, tmp_wnode);
				wipsd_cmd_send(treebuf, cfd);
			}
			wipsd_free(mp->node);
			break;
		case LIST_TASK_TREE_GET_ALL_ESSID:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				tree_get_all_essid(treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;
		case LIST_TASK_TREE_GET_BY_CHANNEL:
			tmp_wnode = (struct w_node *)mp->node;
			cfd = tmp_wnode->refresh_time;
			if(cfd > 0){
				treebuf->len =0;
				tree_get_by_channel(treebuf, tmp_wnode);
				wipsd_cmd_send(treebuf, cfd);
			}
			wipsd_free(mp->node);
			break;
		case LIST_TASK_TREE_GET_ALL_CHANNEL:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				tree_get_all_channel(treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;

		case LIST_TASK_TREE_GET_ISLANDSTA_BY_CHANNEL:
			tmp_wnode = (struct w_node *)mp->node;
			cfd = tmp_wnode->refresh_time;
			if(cfd > 0){
				treebuf->len =0;
				tree_get_islandsta_by_channel(treebuf, tmp_wnode);
				wipsd_cmd_send(treebuf, cfd);
			}
			wipsd_free(mp->node);
			break;
		case LIST_TASK_TREE_GET_ISLANDSTA_ALL_CHANNEL:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				tree_get_islandsta_all_channel(treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;
		case LIST_TASK_TREE_BLOCK_WITH_A_ESSID:
			tmp_wnode = (struct w_node *)mp->node;
			block_sta_with_a_essid(tmp_wnode);
			wipsd_free(mp->node);
			break;
#endif


#ifdef MIPS
#if 0
     	case LIST_ATTACK:
			cfd = *((int *)mp->node);
			wipsd_free(mp->node);
			if(cfd > 0){
				treebuf->len =0;
				tree_get_attack_list(treebuf);
				wipsd_cmd_send(treebuf, cfd);
			}
			break;
#endif
#endif
		case LIST_TASK_CREATE_FAKE_AP:
			/*tmp_wnode = (struct w_node *)mp->node;
			tmp_wnode->child_num = ADD_AP;
			if(re_create_recv_socket != RE_CREATE_RECV_SOCKET){
				auto_operating_fakeap(tmp_wnode, 0);
			}*/
			XFREE(MTYPE_WIPS_DEBUG_WNODE_CHANGE,mp->node);
			break;
#if 0
		case LIST_TASK_DELETE_FAKE_AP:
			/*tmp_wnode = (struct w_node *)mp->node;
			tmp_wnode->child_num = DEL_AP;
			if(re_create_recv_socket != RE_CREATE_RECV_SOCKET){
				auto_operating_fakeap(tmp_wnode, 0);
			}*/
			wipsd_free(mp->node);
			break;
#endif
		default :
			WIPSD_DEBUG("unknown list_task type!\n");
			if(mp->node)
				free(mp->node);
			break;
	}
//	wipsd_free(treebuf);
	XFREE(MTYPE_WIPS_DEBUG_MP_NODE,mp);

	list_task_tmp = 255;

}

#ifdef MIPS
void tree_get_attack_list(ListBuf* treebuf)
{
	treebuf->len = snapshot_event_memlog(treebuf->buf, EVENT_MEM_LOGGER_BUFFERSIZE);
	treebuf->len = treebuf->len > EVENT_MEM_LOGGER_BUFFERSIZE ? EVENT_MEM_LOGGER_BUFFERSIZE : treebuf->len;
	treebuf->len *= sizeof(struct event_memlog_pkt);
	struct attack_share_pkt aspkt = { .wevent_key=wevent_listid, .wevent_kindnum=wevent_num, .wevent_grpnum=wevent_grp_num };
	*(struct attack_share_pkt*)(((char*)&treebuf->buf[0])+treebuf->len) = aspkt;
	treebuf->len += sizeof(struct attack_share_pkt);
}
#endif

void insertListTask(struct list_tast *mp)
{
	if(list_tast_rear == NULL && list_tast_head == NULL)
	{
		list_tast_head=list_tast_rear=mp;
		mp->next=NULL;
	}else{
		mp->next=NULL;
		list_tast_rear->next=mp;
		list_tast_rear=mp;
	}
	if(mp->task_type == LIST_TASK_GETAPWLIST ||
	   mp->task_type == LIST_TASK_GETSTAWLIST ||
	   mp->task_type == LIST_TASK_GETWNODE)
		cmd_highest_priority++;
}

static inline int push_fd(int fd)
{
	int i;
	if(fd <= 0) return -2;
	for(i=1; i<FD_MAX; i++){
		if(fd_CMD[i] <= 0){
			fd_CMD[i] = fd;
			return i;
		}
	}
	for(i=1; i<FD_MAX; i++){
		close(fd_CMD[i]);
		fd_CMD[i] = 0;
	}
	fd_CMD[1] = fd;
	return 1;
}

#if 0
//======================================
int CMD_init(int *lfd,char *path)
{
	int fd,len;
	struct sockaddr_un un;

	if((fd=socket(AF_UNIX,SOCK_STREAM,0))==-1){
		perror("Fail to socket");
		return -1;
	}

	unlink(path);
	memset(&un,0,sizeof(un));
	un.sun_family=AF_UNIX;
	strcpy(un.sun_path,path);

	len=offsetof(struct sockaddr_un,sun_path)+strlen(path);
	if(bind(fd,(struct sockaddr *)&un,len)==-1){
		perror("Fail to bind");
		goto err;
	}

	if(listen(fd,10)==-1){
		perror("Fail to listen");
		goto err;
	}

	*lfd=fd;
	return 0;

err:
	close(fd);
	return -1;
}

int CMD_init_recv_socket(char * path)
{
	int sockfd,len;
	int ret;
	struct sockaddr_un addr;
	sockfd=socket(AF_UNIX,SOCK_STREAM,0);
	if(sockfd<0)
	{
		perror("CMD_init_recv_socket_GETFDERR\n");
		exit(-1);
	}

	unlink(path);
	bzero(&addr,sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	len=offsetof(struct sockaddr_un,sun_path)+strlen(path);
	if(bind(sockfd,(struct sockaddr *)&addr,len)<0)
	 {
		perror("CMD_init_recv_socket_BINDERR\n");
		close(sockfd);
		exit(-1);
	 }


	if(listen(sockfd,10)==-1){
		perror("Fail to listen");
		close(sockfd);
		exit(-1);
	}

	ret = system("chmod 777 "PATH);
	return sockfd;
}

void * CMD_task(void *p)
{
	int lfd,cfd,len,n;
	int ret;
	time_t staletime;
	struct sockaddr_un un;
	struct stat statbuf;
	char buf[MSG_SIZE];
	ListBuf *treebuf_tmp;
	__u8 mac[8];

	cfd = 0;
begin:

	if(CMD_init(&lfd,PATH)==-1){
		goto begin;
	}
	WIPSD_DEBUG("CMD_task running!\n");

	ret = system("chmod 777 /tmp/wireless_s");
	while(wireless_enable){
//============================================================
		len=sizeof(struct sockaddr_un);
		if((cfd=accept(lfd,(struct sockaddr *)&un,(socklen_t * __restrict__)&len))==-1){
			perror("Fail to accept");
			continue;
		}
		len-=offsetof(struct sockaddr_un,sun_path);
		un.sun_path[len]='\0';

		if(stat(un.sun_path,&statbuf)==-1){
			perror("Fail to get status");
			close(cfd);
			continue;
		}
		if((statbuf.st_mode&(S_IRWXG|S_IRWXO))||(statbuf.st_mode&S_IRWXU)!=S_IRWXU){
			WIPSD_DEBUG("wrong permissions\n");
			close(cfd);
			continue;
		}
		staletime=time(NULL)-STALE;
		if(statbuf.st_atime<staletime||statbuf.st_ctime<staletime||statbuf.st_mtime<staletime){
			WIPSD_DEBUG("client is too old\n");
			close(cfd);
			continue;
		}

		if(unlink(un.sun_path)==-1){
			perror("Fail to unlink");
			close(cfd);
			continue;
		}

		struct timeval timeout = {2,0};
		setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));
		n=read(cfd,buf,MSG_SIZE);
		if (n==-1){
			perror("Fail to read");
			close(cfd);
			continue;
		}else if(n<=0){
			WIPSD_DEBUG("the connect closed\n");
			close(cfd);
			continue;
		}
//============================================================
		buf[n] = '\0';
		//WIPSD_DEBUG("CMD Server Recv:%s\n",buf);

		//func code
		if(strncmp(buf, "get_start_flag", 14)  == 0)
		{
			int flag = 0;
			flag = start_flag;

			//WIPSD_DEBUG("flg = %d \n", flag);

			int len=write(cfd, (char *)&flag,sizeof(int));
			if(len != sizeof(int)){
				WIPSD_DEBUG("Cmd list write start flag error !\n");
				close(cfd);
				continue;
			}

			close(cfd);

		}else
		if(strncmp(buf, "get_ap_num",10) == 0)
		{
			struct save_elem_wnode elem;
			bzero((char *)&elem,sizeof(elem));

			if(debug_ap_number < 0)
				elem.ap_num = 0;
			else
				elem.ap_num = debug_ap_number;

			if(debug_sta_number < 0)
				elem.station_num = 0;
			else
				elem.station_num = debug_sta_number;

			int len=write(cfd, (char *)&elem,sizeof(struct save_elem_wnode));
			if(len != sizeof(struct save_elem_wnode)){
				WIPSD_DEBUG("Cmd list write save elem error !\n");
				close(cfd);
				continue;
			}

			close(cfd);


		}else
		if(strcmp(buf,"aplist")==0){
			struct list_tast *mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
				//sem_destroy(&sem);
				//goto begin;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_GETAPWLIST;
			insertListTask(mp);
		} else if(strcmp(buf,"stalist")==0){
			struct list_tast *mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_GETSTAWLIST;
			insertListTask(mp);
		} else if(strncmp(buf, "ssid[", 5)==0){
		/*
		*	usage: getwlist ssid[your ssid]iface[athX]ch[channel]type[non/wep/wpa]
		*/
			char *buff;
			int i;
			char iface[55];
			char ssid[255];
			char ch=1;
			close(cfd);
			buff = buf+5;
			for(i=5;i<MSG_SIZE;i++){
				if(buf[i] == ']') {
					buf[i] = '\0';
					break;
				}
			}
			if(i-5 < 255){
				strcpy( ssid, buff);
				i+=1;
				buff = buf+i;
				if(strncmp(buff, "iface[", 6)==0){
					int j;
					i+=6;
					j = i;
					buff = buf+i;
					for(;i<(MSG_SIZE-j);i++){
						if(buf[i] == ']'){
							buf[i] = '\0';
							break;
						}
					}
					if((i-j) < 55){
					strcpy( iface, buff);
					i+=1;
					buff = buf+i;
					if(strncmp(buff, "ch[", 3)==0){
						i+=3;
						j = i;
						buff = buf+i;
						for(;i<(MSG_SIZE-j);i++){
							if(buf[i] == ']'){
								buf[i] = '\0';
								break;
							}
						}
						if((i-j) < 3){
							ch = atoi(buff);
							i+=1;
							buff = buf+i;
							if(strncmp(buff, "type[", 5)==0){
								i+=5;
								j = i;
								buff = buf + i;
								for(;i<(MSG_SIZE-j);i++){
									if(buf[i] == ']') break;
								}
								/*if(i - j == 3){
									if(strncmp(buff, "wep", 3)==0){
										create_fakeap(iface, ssid, ch, FAKE_WEP);
									}else if(strncmp(buff, "wpa", 3)==0){
										create_fakeap(iface, ssid, ch, FAKE_WPA);
									}else if(strncmp(buff, "non", 3)==0){
										create_fakeap(iface, ssid, ch, FAKE_OPEN);
									}
								}*/
							}
						}
					}
					}
				}
			}

		} else if(strncmp(buf, "wnode", 5)==0){
			char buff[1024];
			treebuf_tmp = (ListBuf *)buff;
			if(n < 22){
				sprintf((char *)treebuf_tmp->buf, "error:no mac string--%s", buf);
				perror((char *)treebuf_tmp->buf);
				ret = write(cfd,(char *)treebuf_tmp, sizeof(struct w_node) + sizeof(int));
				close(cfd);
				continue;
			}

			struct list_tast *mp=NULL;
			struct w_node * fdp = NULL;
			fdp = malloc(sizeof(struct w_node));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			buf[22] = '\0';
			str2mac(mac, (char *)&buf[5]);
			fdp->noise = push_fd(cfd);
			memcpy(fdp->mac , mac, sizeof(fdp->mac));
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_GETWNODE;
			insertListTask(mp);
		} else if(strncmp(buf, "update_policy", 13)==0){
			char buff[100];

			wpolicy_update_tag = 1;
			treebuf_tmp = (ListBuf *)buff;
			sprintf((char *)treebuf_tmp->buf, "cmd_ok");
			treebuf_tmp->len = strlen((char *)treebuf_tmp->buf);
			if(write(cfd,(char *)treebuf_tmp, treebuf_tmp->len + sizeof(int))==-1){
				perror("Fail to write");
			}
			close(cfd);
		}else if(strcmp(buf,"cara")==0){
			char cmd[255],ret;
			close(cfd);

			sprintf(cmd,"echo \"wireless_enable[%d]--wips_enbale[%d]\" >> /tmp/wdbug",
				wireless_enable, wips_enbale);
			ret = system(cmd);
			WIPSD_DEBUG("wireless_enable[%d]--wips_enbale[%d]\n",
				wireless_enable, wips_enbale);

			sprintf(cmd,"echo \"listask_polln[%d]\" >> /tmp/wdbug",listask_polln);
			ret = system(cmd);
			WIPSD_DEBUG("listask_polln[%d]\n",listask_polln);

			sprintf(cmd,"echo \"debug_ap_number[%d]--debug_sta_number[%d]\" >> /tmp/wdbug",
				debug_ap_number,debug_sta_number);
			ret = system(cmd);
			WIPSD_DEBUG("debug_ap_number[%d]--debug_sta_number[%d]\n",
				debug_ap_number,debug_sta_number);

			sprintf(cmd,"echo \"wips_sensitivity[%d]\" >> /tmp/wdbug",wips_sensitivity);
			ret = system(cmd);
			WIPSD_DEBUG("wips_sensitivity[%d]\n",wips_sensitivity);

			sprintf(cmd,"echo \"monitor_alert[%d]\" >> /tmp/wdbug",monitor_alert);
			ret = system(cmd);
			WIPSD_DEBUG("monitor_alert[%d]\n",monitor_alert);

			sprintf(cmd,"echo \"log_mode[%d]\" >> /tmp/wdbug",log_mode);
			ret = system(cmd);
			WIPSD_DEBUG("log_mode[%d]\n",log_mode);

			sprintf(cmd,"echo \"monitor_band[%d]\" >> /tmp/wdbug",monitor_band);
			ret = system(cmd);
			WIPSD_DEBUG("monitor_band[%d]\n",monitor_band);

			sprintf(cmd,"echo \"packet_counter4show[%d]\" >> /tmp/wdbug",packet_counter4show);
			ret = system(cmd);
			WIPSD_DEBUG("packet_counter4show[%d]\n",packet_counter4show);

			sprintf(cmd,"echo \"blocking_number[%d]\" >> /tmp/wdbug",blocking_number);
			ret = system(cmd);
			WIPSD_DEBUG("blocking_number[%d]\n",blocking_number);

			sprintf(cmd,"echo \"PKG_num[%d]\" >> /tmp/wdbug",PKG_num);
			ret = system(cmd);
			WIPSD_DEBUG("PKG_num[%d]\n",PKG_num);

			sprintf(cmd,"echo \"wireless_node_age[%d]\" >> /tmp/wdbug",wireless_node_age);
			ret = system(cmd);
			WIPSD_DEBUG("wireless_node_age[%d]\n",wireless_node_age);

//=================================================================
			static int recv_pre=0;
			static long old__t=0,new__t=10;
			sprintf(cmd, "echo \"recv[%d]	send[%d]--send_err[%d]	start_at[%d]s--now[%ld]s	rps_a[%ld]--rps[%ld]	sps[%ld]--err_sps[%ld]\" >> /tmp/wdbug",
				recv_packet,
				send_number,
				send_err_num,
				tmp_t,
				fresh_time,
				recv_packet/(fresh_time - tmp_t),
				(recv_packet - recv_pre)/(new__t - old__t),
				send_number/(fresh_time - tmp_t),
				send_err_num/(fresh_time - tmp_t));
			ret = system(cmd);
			WIPSD_DEBUG("recv[%d]	send[%d]--send_err[%d]	start_at[%d]s--now[%ld]s	rps_a[%ld]--rps[%ld]	sps[%ld]--err_sps[%ld]\n",
				recv_packet,
				send_number,
				send_err_num,
				tmp_t,
				fresh_time,
				recv_packet/(fresh_time - tmp_t),
				(recv_packet - recv_pre)/(new__t - old__t),
				send_number/(fresh_time - tmp_t),
				send_err_num/(fresh_time - tmp_t));
			recv_pre =recv_packet;
			old__t = new__t;
			new__t = fresh_time;
			sprintf(cmd, "echo \"packet_counter__nps[%ld]	blocking_number[%d] nps[%ld]	pth_number[%lld]_nps[%lld]\" >> /tmp/wdbug",
				packet_counter4show/(fresh_time - tmp_t),
				blocking_number,
				blocking_number/(fresh_time - tmp_t),
				pth_number,
				pth_number/(fresh_time - tmp_t));
			ret = system(cmd);
			WIPSD_DEBUG("packet_counter__nps[%ld]	blocking_number[%d] nps[%ld]	pth_number[%lld]_nps[%lld]\n\n\n",
				packet_counter4show/(fresh_time - tmp_t),
				blocking_number,
				blocking_number/(fresh_time - tmp_t),
				pth_number,
				pth_number/(fresh_time - tmp_t));
//=================================================================
			ret = system("echo \"===========================================\" >> /tmp/wdbug\n\n");
		}else if(strcmp(buf,"clean_cara")==0){
			close(cfd);
			tmp_t = fresh_time;
			recv_packet=0;
			send_number=0;
			send_err_num=0;
			blocking_number=0;
			pth_number=0;
			packet_counter4show  = 0;
		}else if(strcmp(buf,"check_list")==0){
			struct list_tast *mp=NULL;
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL){
				WIPSD_DEBUG("malloc for new list_task err!\n");
			}else{
				memset(mp,0,sizeof(struct list_tast));
				mp->task_type= LIST_TASK_CHECKWLIST;
				insertListTask(mp);
			}
			close(cfd);
		}else if(strcmp(buf,"print_pac")==0){
			if(debug_wpackage_WIPSD_DEBUG_en){
				debug_wpackage_WIPSD_DEBUG_en=0;
			}else{
				debug_wpackage_WIPSD_DEBUG_en=1;
			}
			close(cfd);
		}else if(strncmp(buf, "update_wconfig", 14)==0){
			char buff[100];

			wconfig_update_tag = 1;
			treebuf_tmp = (ListBuf *)buff;
			sprintf((char *)treebuf_tmp->buf, "cmd_ok");
			treebuf_tmp->len = strlen((char *)treebuf_tmp->buf);
			if(write(cfd,(char *)treebuf_tmp, treebuf_tmp->len + sizeof(int))==-1){
				perror("Fail to write");
			}
			close(cfd);
		}else if(strcmp(buf,"refd")==0){
			close(cfd);
			re_create_recv_socket = RE_CREATE_RECV_SOCKET;
			WIPSD_DEBUG("re_create_recv_socket[%d]!\n",re_create_recv_socket);
		}else if(strcmp(buf,"cc=3")==0){
			cc = (1 << 0) |(1 << 1) | (1 << 2);
			WIPSD_DEBUG("cc[%d]!\n",cc);
			close(cfd);
		}else if(strcmp(buf,"cc=2")==0){
			cc = (1 << 0) |(1 << 1) ;
			WIPSD_DEBUG("cc[%d]!\n",cc);
			close(cfd);
		}else if(strcmp(buf,"cc=1")==0){
			cc = (1 << 0) ;
			WIPSD_DEBUG("cc[%d]!\n",cc);
			close(cfd);
		}else if(strcmp(buf,"bd=2")==0){
			monitor_band = 2 ;
			WIPSD_DEBUG("monitor_band[%d]!\n",monitor_band);
			close(cfd);
		}else if(strcmp(buf,"bd=5")==0){
			monitor_band = 5 ;
			WIPSD_DEBUG("monitor_band[%d]!\n",monitor_band);
			close(cfd);
		}else if(strcmp(buf,"bd=25")==0){
			monitor_band = 25 ;
			WIPSD_DEBUG("monitor_band[%d]!\n",monitor_band);
			close(cfd);
		}else if(strcmp(buf,"TREE_GET_ESSID_NAME_ID")==0){
			struct list_tast *mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_TREE_GET_ESSID_NAME_ID;
			insertListTask(mp);
		}else if(strncmp(buf, "TREE_GET_BY_ESSID_ID", 20)==0){
			struct list_tast *mp=NULL;
			struct w_node * node=NULL;
			char * buff = &buf[20];
			node = malloc(sizeof(struct w_node));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || node == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(node);
				continue;
			}
			memset(node,0,sizeof(struct w_node));
			memset(mp,0,sizeof(struct list_tast));
			node->refresh_time = push_fd(cfd);
			memcpy(node->essid_id, SSID_SEQUENCE_HEAD, 5);
			node->essid_id[5] = atoi(buff);;
			mp->node = (void *)node;
			mp->task_type= LIST_TASK_TREE_GET_BY_ESSID_ID;
			insertListTask(mp);
		}else if(strncmp(buf, "TREE_GET_BY_A_ESSID", 19)==0){
			struct list_tast *mp=NULL;
			struct w_node * node=NULL;
			char * buff = &buf[19];
			node = malloc(sizeof(struct w_node));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || node == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(node);
				continue;
			}
			memset(node,0,sizeof(struct w_node));
			memset(mp,0,sizeof(struct list_tast));
			node->refresh_time = push_fd(cfd);
			strncpy( node->ssid, buff,SSID_BUFSIZE_D);
			mp->node = (void *)node;
			mp->task_type= LIST_TASK_TREE_GET_BY_A_ESSID;
			insertListTask(mp);
		}else if(strcmp(buf,"TREE_GET_ALL_ESSID")==0){
			struct list_tast *mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_TREE_GET_ALL_ESSID;
			insertListTask(mp);
		}else if(strncmp(buf, "TREE_GET_BY_CHANNEL", 19)==0){
			struct list_tast *mp=NULL;
			struct w_node * node=NULL;
			char * buff = &buf[19];
			node = malloc(sizeof(struct w_node));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || node == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(node);
				continue;
			}
			memset(node,0,sizeof(struct w_node));
			memset(mp,0,sizeof(struct list_tast));
			node->refresh_time = push_fd(cfd);
			node->channel = atoi(buff);;
			mp->node = (void *)node;
			mp->task_type= LIST_TASK_TREE_GET_BY_CHANNEL;
			insertListTask(mp);
		}else if(strcmp(buf,"TREE_GET_ALL_CHANNEL")==0){
			struct list_tast *mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_TREE_GET_ALL_CHANNEL;
			insertListTask(mp);
		}else if(strncmp(buf, "TREE_GET_ISLANDSTA_BY_CHANNEL", 29)==0){
			struct list_tast *mp=NULL;
			struct w_node * node=NULL;
			char * buff = &buf[29];
			node = malloc(sizeof(struct w_node));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || node == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(node);
				continue;
			}
			memset(node,0,sizeof(struct w_node));
			memset(mp,0,sizeof(struct list_tast));
			node->refresh_time = push_fd(cfd);
			node->channel = atoi(buff);;
			mp->node = (void *)node;
			mp->task_type= LIST_TASK_TREE_GET_ISLANDSTA_BY_CHANNEL;
			insertListTask(mp);
		}else if(strcmp(buf,"TREE_GET_ISLANDSTA_ALL_CHANNEL")==0){
			struct list_tast *mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp == NULL || fdp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type= LIST_TASK_TREE_GET_ISLANDSTA_ALL_CHANNEL;
			insertListTask(mp);
#ifdef MIPS
		}else if(strcmp(buf, "attack_list") == 0){
			struct list_tast* mp=NULL;
			int * fdp = NULL;
			fdp = malloc(sizeof(int));
			mp = malloc(sizeof(struct list_tast));
			if(mp==NULL || fdp==NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				close(cfd);
				wipsd_free(mp);
				wipsd_free(fdp);
				continue;
			}
			memset(mp,0,sizeof(struct list_tast));
			*fdp = push_fd(cfd);
			mp->node = (void *)fdp;
			mp->task_type = LIST_ATTACK;
			insertListTask(mp);
#endif
		}else if(strcmp(buf,"block_deauth=on")==0){
			block_function |= 1;
			WIPSD_DEBUG("block_function[%d]!\n",block_function);
			close(cfd);
		}else if(strcmp(buf,"block_deauth=off")==0){
			block_function &= ~1;
			WIPSD_DEBUG("block_function[%d]!\n",block_function);
			close(cfd);
		}else if(strcmp(buf,"block_arp=on")==0){
			block_function |= 1<<1;
			WIPSD_DEBUG("block_function[%d]!\n",block_function);
			close(cfd);
		}else if(strcmp(buf,"block_arp=off")==0){
			block_function &= ~(1<<1);
			WIPSD_DEBUG("block_function[%d]!\n",block_function);
			close(cfd);
		}else{
			close(cfd);
		}

		//WIPSD_DEBUG("CMD_task end\n");
	}

	WIPSD_DEBUG("CMD Server exit!\n");
	if(unlink(PATH)==-1){
		perror("Fail to unlink");
		exit(1);
	}

	if(cfd > 0)close(cfd);
	close(lfd);
	if(unlink(PATH)==-1){
		perror("Fail to unlink");
	}
	exit(-1);
}
#endif

int node_changed(struct w_node * old_node, int task_type)
#if 0
{
	struct w_node * newnode= NULL;
	struct list_tast *mp=NULL;
	newnode = XMALLOC(MTYPE_WIPS_DEBUG_WNODE_CHANGE,sizeof(struct w_node));
	if(newnode == NULL){
		WIPSD_DEBUG("malloc for new w_node err!\n");
		return -1;
	}
	mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
	if(mp == NULL){
		WIPSD_DEBUG("malloc for new list_task err!\n");
		XFREE(MTYPE_WIPS_DEBUG_WNODE_CHANGE,newnode);
		return -1;
	}
	memset(mp,0,sizeof(struct list_tast));
	memcpy(newnode, old_node, sizeof(struct w_node));
	mp->node = (void *)newnode;
	mp->task_type= task_type;
	insertListTask(mp);
	return 0;
}
#else
{
	return 0;
}
#endif
//pthread_mutex_t wlist_hash_lock = PTHREAD_MUTEX_INITIALIZER;
/*===+++===*/
int init_wlist_hash_table(void)
{
	if ((wlist_hash_table = hash_new()) == NULL){
		WIPSD_DEBUG("hash_new failed");
		return -1;
	}

	if ((nodeinfo_hash_table = hash_new()) == NULL){
		WIPSD_DEBUG("nodeinfo_hash_table hash_new failed");
		return -1;
	}

	return 0;
}

void update_wconfig_list(void)
{
	if(!wconfig_update_tag)
		return;

	//WIPSD_DEBUG("update_wconfig_list\n");
	wconfig_update_tag = 0;

	get_wireless_config();
	return;
}

int get_wlist_node(char * mac, struct w_node ** node_frame)
{
	w_node_list * p_oflist=NULL;
	p_oflist = (w_node_list * )hash_find(wlist_hash_table, (const char *)mac, 6);

	if(p_oflist){
		*node_frame = &p_oflist->b_frame;
		//	memcpy(node_frame, &p_oflist->b_frame, sizeof(struct w_node));
	}else{
		*node_frame = NULL;
		return -1;
	}
	return 0;
}

/*===+++===*/
//sniffer find a node and ...
static int find_wlistnode_sniffer(struct w_node * wnode, int task_type,
		int (*func)(struct w_node * latest,struct w_node * exist) )
{
	w_node_list * p_oflist=NULL;
	p_oflist = (w_node_list * )hash_find(wlist_hash_table, (const char *)&wnode->mac, 6);
	//WIPSD_DEBUG("hash find mac:"NMACQUAD_FMT" p_oflist:%p\n",NMACQUAD(wnode->mac),p_oflist);

	if(p_oflist){
		int ret=0;
		//WIPSD_DEBUG("find_wlistnode_sniffer process call back.\n");
		p_oflist->b_frame.wipsd_itf = wnode->wipsd_itf;
		memcpy((void *)&p_oflist->b_frame.addr, &wnode->addr, sizeof(struct sockaddr_in));

		if((wnode->channel != p_oflist->b_frame.channel
			|| wnode->freq_band != p_oflist->b_frame.freq_band)
			&& p_oflist->b_frame.channel != 0
			&& wnode->channel != 0
			&& wnode->net_type!=NET_TYPE_8021X
	//		&& memcmp( latest->bssid,exist->bssid,6) == 0
			/*&& latest->channel != exist->channel +1
			&& latest->channel != exist->channel -1 */){
		  //if(memcmp(exist->mac, "\xd0\xdf\x9a\x58\x90\x51", 6)==0){
		 /* if(memcmp(exist->mac, "\xe0\x05\xc5\x11\x4c\xbe", 6)==0){
	  WIPSD_DEBUG("sta %s channel changed! %d(old) to %d(new) %d\n", "e0:05:c5:11:4c:be", exist->channel, latest->channel, latest->net_type);
	}*/
			p_oflist->b_frame.channel_changed	=	1;
			p_oflist->b_frame.freq_band			= wnode->freq_band ;
			p_oflist->b_frame.channel			= wnode->channel ;
		}

        // set station sec_type and phy_mode follow with assoc ap
		if (p_oflist->b_frame.node_type & 0x2)
		{
			struct w_node *node_ap=NULL;
			if(//0== p_oflist->b_frame.sec_type[0] && 
			    (p_oflist->b_frame.is_assoc2ap) &&
                (0 == get_wlist_node((char *)&wnode->bssid[0], &node_ap)))
			{
				memcpy(p_oflist->b_frame.sec_type,node_ap->sec_type,sizeof(node_ap->sec_type));
                p_oflist->b_frame.channel = node_ap->channel ;
                p_oflist->b_frame.phy_mode = node_ap->phy_mode;
			}
		}

		ret = (*func)( wnode, &p_oflist->b_frame);
	}else{//add new node

		char signal_tmp = (char )wips_sensitivity;
		if(task_type == NO_ADD_NODE)
			return 0;

		if( wnode->signal < signal_tmp )
			return 0;

		char mac_str[20];
        sprintf(mac_str, NMACQUAD_FMT,NMACQUAD(wnode->mac));
		w_node_list * newnode= NULL;
		struct list_tast *mp=NULL;
		newnode = XMALLOC(MTYPE_WIPS_DEBUG_STA_NODE,sizeof(w_node_list));
		if(newnode == NULL){
			WIPSD_DEBUG("malloc for new wlist_node err!\n");
			return -1;
		}
		mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
		if(mp == NULL){
			WIPSD_DEBUG("malloc for new list_task err!\n");
			XFREE(MTYPE_WIPS_DEBUG_STA_NODE,newnode);
			return -1;
		}
        #if 0
		if(wnode->node_type & 0x1)
		{
    //		int ssid_type =0;
    		nodeInfo * tmp=NULL;
    		tmp = (nodeInfo * )hash_find(nodeinfo_hash_table,
    				(const char *)wnode->mac, 6);
    		if(tmp){
    			int node_type = tmp->node_type & 0x180;
    			if(node_type == 0){//ext
    				wnode->internal_node = FALSE;
    				wnode->ipv4[0] = '\0';
    					WIPSD_DEBUG("func:%s,line:%d ,mac:"MACSTR",ipv4:%s,ipv4[0]:%d  inter: %d\t\n",__func__,__LINE__,MAC2STR(wnode->mac),wnode->ipv4,wnode->ipv4[0],wnode->internal_node);

    			}else if(node_type == 0x80){//in
    				wnode->internal_node = TRUE;
    				if(tmp->ipv4[0] != '\0'){
    					strncpy( wnode->ipv4,tmp->ipv4,sizeof(wnode->ipv4));
    				}
    				clear_wips_event(wnode, WIPS_EID_UNAUTH_AP);
    									WIPSD_DEBUG("func:%s,line:%d ,mac:"MACSTR",ipv4:%s,ipv4[0]:%d  inter: %d\t\n",__func__,__LINE__,MAC2STR(wnode->mac),wnode->ipv4,wnode->ipv4[0],wnode->internal_node);

    			}else{//rogue
    				wnode->internal_node = FALSE;
    				wnode->ipv4[0] = '\0';
    				WIPSD_DEBUG("func:%s ,line:%d  find unauth_ap!\t\n",__func__,__LINE__);
    				report_wips_event(wnode, WIPS_EID_UNAUTH_AP);
    									WIPSD_DEBUG("func:%s,line:%d ,mac:"MACSTR",ipv4:%s,ipv4[0]:%d  inter: %d\t\n",__func__,__LINE__,MAC2STR(wnode->mac),wnode->ipv4,wnode->ipv4[0],wnode->internal_node);

    			}
    			strncpy( wnode->name,tmp->name,sizeof(wnode->name));
    		}
    	}
        #endif
		memset(mp,0,sizeof(struct list_tast));
		memset(newnode,0,sizeof(w_node_list));
		memcpy(&newnode->b_frame, wnode, sizeof(struct w_node));
		strcpy( newnode->b_frame.vendor, P(find_mac_vendor(mac_str)));
		newnode->b_frame.refresh_time = newnode->b_frame.up_time = newnode->b_frame.last_time = fresh_time;
		newnode->b_frame.send_info_timeout = 0;
		if(task_type == LIST_TASK_ADD2STALIST){
			struct w_node *node;
			if(0 == get_wlist_node((char *)newnode->b_frame.bssid, &node)){
				newnode->b_frame.channel = node->channel ;
				newnode->b_frame.freq_band = node->freq_band ;
			    strlcpy(newnode->b_frame.sec_type, node->sec_type, sizeof(newnode->b_frame.sec_type));
                if(newnode->b_frame.phy_mode == IEEE80211_MODE_AUTO)
                    newnode->b_frame.phy_mode = node->phy_mode;
			}
		}
		mp->node = (void *)newnode;
		mp->task_type= task_type;
		insertListTask(mp);
	}
	return 0;
}

/*===+++===*/
static int add_wlistnode( w_node_list * p_oflist, w_node_list ** header,
		w_node_list ** tail)
{
	w_node_list * p_tmp = NULL;

	if(memcmp( p_oflist->b_frame.mac,"\x00\x00\x00\x00\x00\x00",6) == 0){
		XFREE(MTYPE_WIPS_DEBUG_STA_NODE,p_oflist);
		return -1;
	}
	if( hash_insert(wlist_hash_table, (const char *)p_oflist->b_frame.mac, 6, (void *)p_oflist) == NULL)
	//	if(1)
		{//add2wlist
		if(*header == NULL && *tail == NULL){
			*header = p_oflist;
			*tail = p_oflist;
		}else if( *tail == NULL){//err
		}else if(*header == NULL){//err
		}else{
			p_tmp = *tail;
			p_tmp->next = p_oflist;
			p_oflist->last = p_tmp;
			*tail = p_oflist;
		}
		#if 1 // mem leak test
		if(!p_oflist->b_frame.ipv4[0]){
			char *ip=NULL;
			char mac_str[20];

			sprintf(mac_str, MACSTR, MAC2STR(p_oflist->b_frame.mac));
			find_lan_ip(mac_str, &ip);
			if(ip) {
				strcpy( p_oflist->b_frame.ipv4, (char *)ip);
				p_oflist->b_frame.internal_node = 1;
				WIPSD_DEBUG(" func:%s get the ip of %s, ip:%s !\t\n",__func__,mac_str,ip);

				XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
			}
		}
		#endif

		if(p_oflist->b_frame.nat_dev == 1)
		{
            clear_wips_event(&p_oflist->b_frame, WIPS_EID_UNAUTH_AP);
			report_wips_event(&p_oflist->b_frame, WIPS_EID_UNAUTH_AP);
		}

	#if 1
		if(p_oflist->b_frame.node_type & 0x02)
			sta_walk_wpolicy(&p_oflist->b_frame, NULL);

		if(p_oflist->b_frame.node_type & 0x01){
			//clear_wips_event(&p_oflist->b_frame, WIPS_EID_NEW_DEVICE_AP);
			report_wips_event(&p_oflist->b_frame, WIPS_EID_NEW_DEVICE_AP);
		}else{
			//clear_wips_event(&p_oflist->b_frame, WIPS_EID_DEVICE_DOWN_STA);
			report_wips_event(&p_oflist->b_frame, WIPS_EID_NEW_DEVICE_STA);
		}

		if(p_oflist->b_frame.node_type & 1){
			channel_root(&p_oflist->b_frame, CHANNEL_AP_ROOT_ADD, p_oflist->b_frame.channel);
			essid_root(&p_oflist->b_frame, ESSID_AP_ROOT_ADD);
		}else if(p_oflist->b_frame.node_type & 2){
			channel_root(&p_oflist->b_frame, CHANNEL_STA_ROOT_ADD, p_oflist->b_frame.channel);
		}

#endif

	}
	else{
		XFREE(MTYPE_WIPS_DEBUG_STA_NODE,p_oflist);
	}

	return 0;
}

static w_node_list * del_wlistnode( w_node_list * p_oflist,
	w_node_list ** header, w_node_list ** tail)
{
	w_node_list * p_tmp, * pp_tmp;
	char mac[24], bssid[24];

	if(p_oflist->b_frame.block == 1 /*&& p_oflist->b_frame.node_type == 1*/) {//delete block node
        sprintf(mac, NMACQUAD_FMT,NMACQUAD(p_oflist->b_frame.mac));
        sprintf(bssid, NMACQUAD_FMT,NMACQUAD(p_oflist->b_frame.bssid));
		//del_block_node_by_blocklist(0, (struct w_node *)&p_oflist->b_frame, p_oflist->b_frame.mac, p_oflist->b_frame.bssid);
	}
	free_blocked_bssid((struct w_node *)&p_oflist->b_frame);

	//del hash_node by mac
	hash_delete(wlist_hash_table, (const char *)&p_oflist->b_frame.mac, 6, 1);

	if(p_oflist->b_frame.node_type & 1){
		channel_root(&p_oflist->b_frame, CHANNEL_AP_ROOT_DEL, p_oflist->b_frame.channel);
		essid_root(&p_oflist->b_frame, ESSID_AP_ROOT_DEL);
	}else if(p_oflist->b_frame.node_type & 2){
		channel_root(&p_oflist->b_frame, CHANNEL_STA_ROOT_DEL, p_oflist->b_frame.channel);
	}
	if(p_oflist == *header && p_oflist == *tail){
		*header = *tail = NULL;
		XFREE(MTYPE_WIPS_DEBUG_STA_NODE,p_oflist);
		return NULL;
	}else if(p_oflist == *header){
		*header = pp_tmp = p_oflist->next;
		pp_tmp->last = NULL;
		XFREE(MTYPE_WIPS_DEBUG_STA_NODE,p_oflist);
		return pp_tmp;
	}else if(p_oflist == *tail){
		*tail = p_tmp = p_oflist->last;
		p_tmp->next = NULL;
		XFREE(MTYPE_WIPS_DEBUG_STA_NODE,p_oflist);
		return NULL;
	}else{
		p_tmp = p_oflist->last;
		pp_tmp = p_oflist->next;
		p_tmp->next = pp_tmp;
		pp_tmp->last = p_tmp;
		XFREE(MTYPE_WIPS_DEBUG_STA_NODE,p_oflist);
		return pp_tmp;
	}
}

//check fresh_time
static int wlist_node_inactive(w_node_list * p_oflist)
{
	int node_time;
	if(wireless_node_dead_time == 0)
		return 0;
	node_time = p_oflist->b_frame.refresh_time;
	if(node_time == 0 ){
		node_time = p_oflist->b_frame.refresh_time = fresh_time;
	}
	if(node_time + wireless_node_dead_time <= fresh_time){
		return 1;
	}
	return 0;//
}

static w_node_list * check_wlistnode( w_node_list * p_oflist,
	w_node_list ** header, w_node_list ** tail,ListBuf * treebuf)
{


	if(wlist_node_inactive(p_oflist)){//return(need del);
		if(1){//if(0 == pthread_mutex_trylock(&p_oflist->list_lock)){
			if(p_oflist->b_frame.node_type & 0x01){
				report_wips_event(&p_oflist->b_frame, WIPS_EID_DEVICE_DOWN_AP);
			}else{
				report_wips_event(&p_oflist->b_frame, WIPS_EID_DEVICE_DOWN_STA);
			}
			return(del_wlistnode(p_oflist,header,tail));//
		}else{//deal data and return(next point);
			return p_oflist->next;
		}
	}else{//deal data and return(next point);
		if(treebuf != NULL){//cp2treebuf
//			pthread_mutex_unlock(&p_oflist->list_lock);
			/*if(1 || (fresh_time > (p_oflist->b_frame.up_time + 5))
				&& !test_wevent_bitmap(WIPS_EID_AIRBASE_NG_FAKE_AP, &p_oflist->b_frame.alert)
				&& !test_wevent_bitmap(WIPS_EID_FAKESSID_AP, &p_oflist->b_frame.alert))*/
			{
				int node_len,buf_maxlen;
				node_len = sizeof(struct w_node);
				buf_maxlen = LISTBUF_MAX;
				if( (buf_maxlen - treebuf->len) >= node_len){
					struct w_node * tmp_node = (struct w_node *)&treebuf->buf[treebuf->len];
					memcpy( &treebuf->buf[treebuf->len], &p_oflist->b_frame, node_len);
					tmp_node->pap = tmp_node->psta = NULL;
					treebuf->len += node_len;
				}else{
					return NULL;
				}
			}
		}else{
//			if(0)check_beacon_ssidAgingTime(&p_oflist->b_frame);

/*			sprintf(mac_str, MACSTR, MAC2STR(p_oflist->b_frame.mac));
			find_lan_ip(mac_str, &ip);

			if(ip) {
				strncpy( p_oflist->b_frame.ipv4, (char * )ip,16);
				wipsd_free(ip);
			}
			else
				p_oflist->b_frame.ipv4[0] = '\0';*/

			if( test_wevent_bitmap(WIPS_EID_WESSID_NG_STA, &p_oflist->b_frame.alert)
				&& (p_oflist->b_frame.interval != 0x0)){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_WESSID_NG_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_AD_HOC, &p_oflist->b_frame.alert)
				&& !(p_oflist->b_frame.node_type & 0x04)){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_AD_HOC);
			}
			if( test_wevent_bitmap(WIPS_EID_ASSO_FLOOD_ACK_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.ack_c,ack_cmax,
								&p_oflist->b_frame.ack_t,ack_tmax  )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_ASSO_FLOOD_ACK_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_ASSO_FLOOD_CTS_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.cts_c,cts_cmax,
								&p_oflist->b_frame.cts_t,cts_tmax  )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_ASSO_FLOOD_CTS_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_ASSO_FLOOD_RTS_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.rts_c,rts_cmax,
								&p_oflist->b_frame.rts_t,rts_tmax  )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_ASSO_FLOOD_RTS_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_ASSO_FLOOD_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.assoc_c,assoc_cmax,
								&p_oflist->b_frame.assoc_c,assoc_cmax  )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_ASSO_FLOOD_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_PROBE_FLOOD_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.prob_req_c,prob_req_cmax,
								&p_oflist->b_frame.prob_req_t,prob_req_tmax )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_PROBE_FLOOD_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_DEAUTH_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.deauth_c,deauth_cmax,
								&p_oflist->b_frame.deauth_t,deauth_tmax )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_DEAUTH_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_DEASSO_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.deassoc_c,deassoc_cmax,
								&p_oflist->b_frame.deassoc_t,deassoc_tmax )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_DEASSO_STA);
			}
			if( test_wevent_bitmap(WIPS_EID_AUTH_FLOOD_STA, &p_oflist->b_frame.alert)
				&& !event_count(&p_oflist->b_frame.auth_c,auth_cmax,
								&p_oflist->b_frame.auth_t,auth_tmax )){
				clear_wips_event(&p_oflist->b_frame, WIPS_EID_AUTH_FLOOD_STA);
			}

			if( 1/*fresh_time > (wireless_node_age + check_crack_time)*/ ) {
				int total_crack;

				total_crack = deauth_cmax*wireless_node_age/deauth_tmax;

				if((p_oflist->b_frame.node_type & 0x02) ) {	//packet from sta to ap
					if( p_oflist->b_frame.deauth_c_crack > 6 /*&& p_oflist->b_frame.deauth_c_crack < total_crack */){
						//p_oflist->b_frame.node_type |= 0x40;
						report_wips_event(&p_oflist->b_frame, WIPS_EID_VIOLENT_CRACK_STA);
						p_oflist->b_frame.auth_c_crack = 0;
						p_oflist->b_frame.deauth_c_crack = 0;
					}else if( p_oflist->b_frame.auth_c_crack > 3){
						//p_oflist->b_frame.node_type |= 0x40;
						report_wips_event(&p_oflist->b_frame, WIPS_EID_VIOLENT_CRACK_STA);
						p_oflist->b_frame.auth_c_crack = 0;
						p_oflist->b_frame.deauth_c_crack = 0;
					}else{
						//p_oflist->b_frame.node_type &= 0xbf;
						clear_wips_event(&p_oflist->b_frame, WIPS_EID_VIOLENT_CRACK_STA);
					}

				} else if((p_oflist->b_frame.node_type & 0x01) ) {		//packet from ap to sta
					if( p_oflist->b_frame.deauth_c_crack > 6 /*&& p_oflist->b_frame.deauth_c_crack < total_crack*/){
						//p_oflist->b_frame.node_type |= 0x40;
						report_wips_event(&p_oflist->b_frame, WIPS_EID_VIOLENT_CRACK_STA);
						p_oflist->b_frame.auth_c_crack = 0;
						p_oflist->b_frame.deauth_c_crack = 0;
					}else{
						//p_oflist->b_frame.node_type &= 0xbf;
						clear_wips_event(&p_oflist->b_frame, WIPS_EID_VIOLENT_CRACK_STA);
					}

				}

				//check_crack_time = fresh_time;
			}

			p_oflist->b_frame.node_type &= 0x7f;	//clear ap+sta

			if(0 && (p_oflist->b_frame.node_type & 0x11) == 0x11){
				w_node_list * p_tmp, * pp_tmp;
				p_oflist->b_frame.node_type &= 0xef;

				if(p_oflist == sta_list_p && p_oflist == sta_list_tail){
					sta_list_p = sta_list_tail = NULL;
				}else if(p_oflist == sta_list_p){
					sta_list_p = pp_tmp = p_oflist->next;
					pp_tmp->last = NULL;
				}else if(p_oflist == sta_list_tail){
					sta_list_tail = p_tmp = p_oflist->last;
					p_tmp->next = NULL;
				}else{
					p_tmp = p_oflist->last;
					pp_tmp = p_oflist->next;
					p_tmp->next = pp_tmp;
					pp_tmp->last = p_tmp;
				}

				if(beacon_list_p == NULL && beacon_list_tail == NULL){
					beacon_list_p = p_oflist;
					beacon_list_tail = p_oflist;
					p_oflist->next = NULL;
					p_oflist->last= NULL;
				}else if( beacon_list_tail == NULL){//err
				}else if(beacon_list_p == NULL){//err
				}else{
					p_tmp = beacon_list_tail;
					p_tmp->next = p_oflist;
					p_oflist->last = p_tmp;
					p_oflist->next = NULL;
					beacon_list_tail = p_oflist;
				}
			}
			if((p_oflist->b_frame.node_type & 0x01) && p_oflist->b_frame.ipv4[0] != '\0'){
				if(memcmp( p_oflist->b_frame.ipv4,"    ",4) != 0){
					add_internal_ssid2list(p_oflist->b_frame.ssid);
				}
			}
			pollingnode(&p_oflist->b_frame);
			if(p_oflist->b_frame.node_type & 0x02){
				struct w_node *node;
				if(0 == get_wlist_node((char *)p_oflist->b_frame.bssid, &node)){
					p_oflist->b_frame.channel		  = node->channel ;
				}
			}
			if(p_oflist->b_frame.node_type & 0x02){
				if(0&&(memcmp( p_oflist->b_frame.bssid,"\xff\xff\xff\xff\xff\xff",6) != 0)
					&& (memcmp( p_oflist->b_frame.bssid,"\x00\x00\x00\x00\x00\x00",6) != 0)){
					w_node_list * p_tmp=NULL;
					p_tmp = (w_node_list * )hash_find(wlist_hash_table,
						(const char *)p_oflist->b_frame.bssid, 6);
					if(p_tmp){
						p_tmp->b_frame.sta_number++ ;
					}
				}
				if(p_oflist->b_frame.reasso_mark & 1
					&& ((p_oflist->b_frame.reasso_time + 5) < fresh_time)){
					if(p_oflist->b_frame.linked_c != 0xff00){
						report_wips_event(&p_oflist->b_frame, WIPS_EID_REASSO_REFUSED);
						p_oflist->b_frame.reasso_mark = 0;
					}
				}
				if(p_oflist->b_frame.wpa8021x_mark & 1
					&& ((p_oflist->b_frame.wpa_time + 5) < fresh_time)){
					if(p_oflist->b_frame.linked_c != 0xff00){
						report_wips_event(&p_oflist->b_frame, WIPS_EID_WPA_REFUSED);
						p_oflist->b_frame.wpa8021x_mark = 0;
					}
				}
				if(p_oflist->b_frame.auth_mark == 1
					&& ((p_oflist->b_frame.auth_time + 5) < fresh_time)){
					if(p_oflist->b_frame.linked_c != 0xff00){
						report_wips_event(&p_oflist->b_frame, WIPS_EID_AUTH_REFUSED);
						p_oflist->b_frame.auth_mark = 0;
					}
				}
				if(p_oflist->b_frame.probe_noauth_mark == 1
					&& ((p_oflist->b_frame.probe_noauth_time + 5) < fresh_time)){
					if(memcmp( p_oflist->b_frame.bssid,p_oflist->b_frame.pro_bssid,6) != 0){
						report_wips_event(&p_oflist->b_frame, WIPS_EID_PROBE_NOAUTH);
						p_oflist->b_frame.auth_mark = 0;
					}else{
						p_oflist->b_frame.auth_mark = 0;
					}
				}
				if(p_oflist->b_frame.probe_req_mark == 3
					&& ((p_oflist->b_frame.probe_req_time + 5) < fresh_time)){
					report_wips_event(&p_oflist->b_frame, WIPS_EID_PROBE_REFUSED);
					p_oflist->b_frame.probe_req_mark = 0;
				}else if(p_oflist->b_frame.probe_req_mark == 1
					&& ((p_oflist->b_frame.probe_req_time + 5) < fresh_time)){
					p_oflist->b_frame.probe_req_mark = 0;
				}
			}
			if(p_oflist->b_frame.node_type & 0x01){
				if(check_default_ssid(p_oflist->b_frame.ssid)){
					report_wips_event(&p_oflist->b_frame, WIPS_EID_AP_DEFAULTSSID);
				}
				if(check_apnumber_eachchannel(p_oflist->b_frame.channel, 0)){
					report_wips_event(&p_oflist->b_frame, WIPS_EID_TOOMANY_AP_INACHANNEL);
				}
				if(p_oflist->b_frame.sta_number > 25 && p_oflist->b_frame.open_qos > 0){
					report_wips_event(&p_oflist->b_frame, WIPS_EID_AP_TOOMANY_QBSSSTA);
				}
				if(check_ap_essid_seting(&p_oflist->b_frame, 0)){
					report_wips_event(&p_oflist->b_frame, WIPS_EID_AP_ESSID_DIFF);
				}
			}
			if(check_adhoc_ap_ssid(&p_oflist->b_frame, 0)){
				report_wips_event(&p_oflist->b_frame, WIPS_EID_ADHOC_SSID_AP_SSID_SAME);
			}
		}
		return p_oflist->next;
	}
}

/*===+++===*/
int check_wlist(w_node_list ** header, w_node_list ** tail,ListBuf * treebuf)
{
	w_node_list * p_tmp;
	int num =0;

	if(*header == NULL || *tail == NULL){return -1;}

	p_tmp = *header;
	for(;;){
		num++;
		p_tmp = check_wlistnode( p_tmp, header, tail, treebuf);
		if(p_tmp == NULL)
			break;//return 0;
	}

	return num;
}

static int consistent_num(__u8 * macA,__u8 * macB)
{
	int num=0;
	if(macA[0] == macB[0]){
		num++;
	}
	if(macA[1] == macB[1]){
		num++;
	}
	if(macA[2] == macB[2]){
		num++;
	}
	if(macA[3] == macB[3]){
		num++;
	}
	if(macA[4] == macB[4]){
		num++;
	}
	if(macA[5] == macB[5]){
		num++;
	}
	return num;
}

static w_node_list * check_stalistnode( w_node_list * p_oflist,
	w_node_list ** header, w_node_list ** tail,struct w_node * node)
{
	int findSTA = 0;
//	pthread_mutex_lock(&p_oflist->list_lock);
	if(consistent_num(p_oflist->b_frame.mac ,node->mac) == 6){
		findSTA = 1;
		p_oflist->b_frame.node_type |= 0x80;
		node->node_type |= 0x80;
	}else if(p_oflist->next == NULL){
		p_oflist->b_frame.node_type &= 0x7f;
		node->node_type &= 0x7f;
	}
//	pthread_mutex_unlock(&p_oflist->list_lock);
	if(findSTA)
		return NULL;
	else
		return p_oflist->next;
}

/*===+++===*/
int check_stalist(w_node_list ** header, w_node_list ** tail,struct w_node * node)
{
	w_node_list * p_tmp;

	if(*header == NULL || *tail == NULL){return -1;}
	if(node == NULL){return -1;}

	p_tmp = *header;
	for(;;){
		p_tmp = check_stalistnode( p_tmp, header, tail, node);
		if(p_tmp == NULL) break;//return 0;
	}

	return 0;
}

static w_node_list * update_sta_node_waction( w_node_list * p_oflist,
	w_node_list ** header, w_node_list ** tail,ListBuf * treebuf)
{
//	pthread_mutex_lock(&p_oflist->list_lock);

	sta_walk_wpolicy(&p_oflist->b_frame, NULL);

//	pthread_mutex_unlock(&p_oflist->list_lock);
	return p_oflist->next;
}

/*===+++===*/
static int update_sta_waction(w_node_list ** header, w_node_list ** tail,ListBuf * treebuf)
{
	w_node_list * p_tmp;

	if(*header == NULL || *tail == NULL){return -1;}

	p_tmp = *header;

//		init_bn_hitbit(cur_freq);
	for(;;){
		p_tmp = update_sta_node_waction( p_tmp, header, tail, treebuf);
		if(p_tmp == NULL) break;//return 0;
	}
//		clear_bn_by_hitbit(cur_freq);

	return 0;
}
//===============================================================================================

#if 0
int find_unauthorized_ap(struct w_node *ap_val)
{
	sqlite3 *sql = NULL;
	int ret, row=0, col=0;
	char query[256];
	char mac[24];
	char **dbResult;
	char *errmsg;

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite wconfig.db error !");
		return 0;
	}

    sprintf(mac, NMACQUAD_FMT,NMACQUAD(ap_val->mac));

	sprintf(query,"select * from aplist where wmac=\"%s\" or mmac=\"%s\"", mac, mac);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);

    if(sql)
    	wipsd_sqlite3_close(sql);

	if(row > 0) {
		clear_wips_event(ap_val, WIPS_EID_UNAUTH_AP);
		return 0;
	}
	else {
		report_wips_event(ap_val, WIPS_EID_UNAUTH_AP);
		return 1;
	}
}
#endif
int iface_socket_setrate(interface_wlan * piface)
{
	if(ioctl(piface->fd, SIOCSIWRATE, &piface->wrq) != 0)
	{
		perror("ioctl(SIOCSIWRATE)");
	}
	return 0;
}
int iface_socket_setchannel(interface_wlan * piface, __u32 channel)
{
	piface->wrq.u.freq.m = channel;
	if(ioctl(piface->fd, SIOCSIWFREQ, &piface->wrq) != 0)
	{
		perror("ioctl(SIOCSIWFREQ)");
	}
	return 0;
}

int iface_socket_send(interface_wlan * piface, wipsd_block_list * blocPac)
{
	int ret;
	ret = sendto(piface->fd, blocPac->buf, blocPac->pacLength,
				0, (struct sockaddr *)&piface->addr, sizeof(piface->addr));
	return ret;
//	ret = sendto(s, deauth, sizeof(deauth), 0, (struct sockaddr *)&addr, sizeof(addr));
}

int iface_socket_recv(interface_wlan * piface, __u8 * buf,int buf_len)
{
	int len;
	len = recvfrom(piface->fd, buf, buf_len, MSG_DONTWAIT, NULL, NULL);
	//len = recvfrom(piface->fd, buf, buf_len, MSG_WAITALL, NULL, NULL);
	if (0/*len < 0*/){
		perror("recvfrom");
		close(piface->fd);
		exit(-1);
	}
//	WIPSD_DEBUG("iface_socket_recv recvfrom len = %x\n",len);
	return len;
}
#if 0
int sniffer(interface_wlan *piface)
{
	__u8 buf[8192];
	int len;
	int tmp_trice=0;
sniffer_again:
	//setup wireless param(channel/rate/txpower)
	len = iface_socket_recv(piface, buf,8192);

	if(len>0) {
		packet_counter++;
		packet_counter4show++;
		if( insert_PKG(buf, len) == -1){
			//tmp_trice++;
			if(tmp_trice<10)
				goto sniffer_again;
		}
	}
	else
		usleep(500);

	if( recv_packet && check_packet_counter) {
		check_packet_counter = 0;
		if(packet_counter <= 0) {
			re_create_recv_socket = RE_CREATE_RECV_SOCKET;
			recv_packet = 0;
		}
		packet_counter = 0;
	}

	return 0;
}

int insert_PKG(__u8 *buf, int len)
{
	struct list_tast *mp=NULL;
	void * node;

	if(buf == NULL || len <= 26) goto err_out;

	__u32 msg = *((__u32 *)(&buf[0]));
	if(msg == 0x44 && len < 7995){
	}else if( buf[0] || buf[1] || (24 + buf[2]) >= len || len > 2346){
		goto err_out;
	}else{
		goto err_out;
	}

	node = malloc(len);
	mp = malloc(sizeof(struct list_tast));
	if(mp == NULL || node == NULL){
		WIPSD_DEBUG("malloc for new PKG_task err!\n");
		goto err;
	}
	memcpy( node,buf,len);
	mp->task_type= len;
	mp->node = node;

	if( 0 == pthread_mutex_trylock(&PKG_task_lock)){
		if(PKG_num >= 5000){
			pthread_mutex_unlock(&PKG_task_lock);
			goto err;
		}
		PKG_num++;
		if(PKG_tast_rear == NULL && PKG_tast_head == NULL){
			PKG_tast_head=PKG_tast_rear=mp;
			mp->next=NULL;
		}else{
			mp->next=NULL;
			PKG_tast_rear->next=mp;
			PKG_tast_rear=mp;
		}
		pthread_mutex_unlock(&PKG_task_lock);
	}else{
		goto err;
	}
	return 0;

err:
	wipsd_free(node);
	wipsd_free(mp);
err_out:
	return -1;
}
#endif
/*------------------------------------------------------------------------*
*			start
*------------------------------------------------------------------------*/
static const struct ieee80211_rateset pureg[] = {
    {8, {12, 18, 24, 36, 48, 72, 96, 108} },
};

int ieee80211_find_puregrate(u8 rate)
{
    int i;
    
    for (i = 0; i < pureg[0].rs_nrates; i++)
    {
        if (pureg[0].rs_rates[i] == (rate & 0x7f))
            return 1;
    }
    
    return 0;
}

enum ieee80211_phymode
ieee80211_get_phy_type (u8* rates, u8 *xrates, u8 *htcap, u8 *htinfo, u8 *vhtcap, u8 *vhtop, struct w_node * node)
{
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
    
    if (node->freq_band == 2)
    {
        if (htcap && htinfo)
            phymode = IEEE80211_MODE_11NG;
        else if (xrates != NULL)
            phymode = IEEE80211_MODE_11G;
        else 
        {
            if (rates != NULL)
            {
                u8 *tmpPtr  = rates + 2;
                u8 tmpSize = rates[1];
                u8 *tmpPtrTail = tmpPtr + tmpSize;
                int found11g = 0;

                for (; tmpPtr < tmpPtrTail; tmpPtr++)
                {
                    found11g = ieee80211_find_puregrate(*tmpPtr);

                    if (found11g)
                        break;
                }

                if (found11g)
                    phymode = IEEE80211_MODE_11G;
                else
                    phymode = IEEE80211_MODE_11B;
            }
            else 
            {
                phymode = IEEE80211_MODE_11B;
            }
        }
    }
    else
    {
        if (htcap && htinfo)
        {
            if (vhtcap && vhtop)
                phymode = IEEE80211_MODE_11AC;
            else 
                phymode = IEEE80211_MODE_11NA;
        }
        else
        {
            phymode = IEEE80211_MODE_11A;
        }
    }

    return phymode;
}
static int parse_element_tlv(unsigned char *buf, int len, struct w_node * node)
{
    u8 * elem_value = NULL;
    char * pwpa =NULL;
    char * pwpa2=NULL;
    u8 *rates = NULL;
    u8 *xrates = NULL;
    u8 *htcap = NULL;
    u8 *htinfo = NULL;
    u8 *vhtcap = NULL;
    u8 *vhtop = NULL;
    struct ieee80211_ie_header *info_element = NULL;
    int remaining_ie_length = 0;

    len -= fcs;
    info_element = (struct ieee80211_ie_header *)buf;
    remaining_ie_length = len;

    while(remaining_ie_length > sizeof(struct ieee80211_ie_header))
    {
        remaining_ie_length -= sizeof(struct ieee80211_ie_header);

        if (info_element->length == 0)
        {
            info_element += 1;    /* next IE */
            continue;
        }

        if (remaining_ie_length < info_element->length)
        {
            //WIPSD_DEBUG("----------%s-%d:error !!! info_element->length=%d remaining_ie_length=%d------------------\n", __func__, __LINE__, info_element->length, remaining_ie_length);
            break;
        }
        elem_value = (u8 *)info_element + sizeof(struct ieee80211_ie_header);

        switch(info_element->element_id)
        {
            case ELEMENT_ID_SSID:
                node->ssid_len = info_element->length;
                strlcpy(node->ssid, (char *)elem_value, (node->ssid_len < sizeof(node->ssid)) ? node->ssid_len : sizeof(node->ssid));
                //WIPSD_DEBUG("=================  SSID=%s  ===================%d\n", node->ssid, node->ssid_len);
                break;
            case ELEMENT_ID_RATES:
                rates = elem_value;
                if(elem_value[0]>= 0x82)
                    node->b_rates =1;
               // WIPSD_DEBUG("=================    RATES     ===================\n");
                break;
            case ELEMENT_ID_DS:
                if (node->channel != *elem_value)
                {
                    //node->channel = *elem_value;
                }
                break;
            case ELEMENT_ID_EXRATES:
                node->g_rates =1;
                xrates = elem_value;
                //WIPSD_DEBUG("=================  EX_RATES    ===================\n");
                break;
            case ELEMENT_ID_HTCAPA:
                node->n_rates =1;
                htcap = elem_value;
                if(elem_value[0] & 0x02)
                    node->n_20and40 =1;
                //WIPSD_DEBUG("=================  HTCAPA    ===================\n");
                break;
            case ELEMENT_ID_HTINFO:
                htinfo = elem_value;
                //WIPSD_DEBUG("=================  HTINFO    ===================\n");
                break;
            case ELEMENT_ID_VHTCAP:
                vhtcap = elem_value;
                //WIPSD_DEBUG("=================  VHT INFO      ===================\n");
                break;
            case ELEMENT_ID_VHTOP:
                vhtop = elem_value;
                //WIPSD_DEBUG("=================  VHT OP    ===================\n");
                break;
            case ELEMENT_ID_VENDOR:
            {
                u8 *OUI = elem_value;

                if (memcmp(OUI, "\x00\x50\xf2\x01\x01\x00", 6) == 0)//wpa
                {
                    u8 *num_unicast = (OUI + 10);
                    u8 *ucast_oui = num_unicast + 2;
                    u8 *auth_oui = NULL;

                    switch (*num_unicast)
                    {
                        case 0x01:
                            auth_oui = ucast_oui + 6;
                            if (memcmp(ucast_oui, "\x00\x0f\xac\x04", 4)==0)
                            {
                                if (memcmp(auth_oui, "\x00\x50\xf2\x02", 4) == 0)
                                    pwpa = "wpa-aes-psk";
                                else
                                    pwpa = "wpa-aes-802.1X";
                            }
                            else if (memcmp(ucast_oui, "\x00\x0f\xac\x02", 4)==0)
                            {
                                if (memcmp(auth_oui, "\x00\x50\xf2\x02", 4) == 0)
                                    pwpa = "wpa-tkip-psk";
                                else
                                    pwpa = "wpa-tkip-802.1X";
                            }
                            else if (memcmp(ucast_oui, "\x00\x50\xf2\x04", 4)==0)
                            {
                                if (memcmp(auth_oui, "\x00\x50\xf2\x02", 4) == 0)
                                    pwpa = "wpa-aes-psk";
                                else
                                    pwpa = "wpa-aes-802.1X";
                            }
                            else if (memcmp(ucast_oui, "\x00\x50\xf2\x02", 4)==0)
                            {
                                if (memcmp(auth_oui, "\x00\x50\xf2\x02", 4) == 0)
                                    pwpa = "wpa-tkip-psk";
                                else
                                    pwpa = "wpa-tkip-802.1X";
                            }
                            break;
                        case 0x02:
                            auth_oui = ucast_oui + 10;
                            if (memcmp(auth_oui, "\x00\x50\xf2\x02", 4)==0)
                                pwpa = "wpa-tkip-aes-psk";
                            else
                                pwpa = "wpa-tkip-aes-802.1X";
                            break;
                    }
                }
                else if (memcmp(OUI, "\x00\x50\xf2", 3) == 0)
                {
                    u8 *OUI_type = elem_value + 3;
                    switch (*OUI_type)
                    {
                        case 0x02:// wmm
                            node->open_qos = 1;
                            break;
                        case 0x04:// wps
                            node->node_type |=0x20;
                            break;
                        default:
                            break;
                    }
                }
                //WIPSD_DEBUG("=================  ELEMENT_ID_VENDOR pwpa=%s ===================\n", pwpa);
            }
                break;
            case ELEMENT_ID_RSN:
            {
                u8 *pairwise_cnt = elem_value + 6;
                u8 *pairwise_oui = elem_value + 8;
                u8 *akm_oui = NULL;
                switch(*pairwise_cnt)
                {
                    case 0x01: 
                        akm_oui = elem_value + 14;
                        if (memcmp(pairwise_oui, "\x00\x0f\xac\x04", 4)== 0)
                        {
                            if (memcmp(akm_oui, "\x00\x0f\xac\x02", 4) == 0)
                                pwpa2 = "wpa2-aes-psk";
                            else
                                pwpa2 = "wpa2-aes-802.1X";
                        }
                        else if (memcmp(pairwise_oui, "\x00\x0f\xac\x02", 4)==0)
                        {
                            if (memcmp(akm_oui, "\x00\x0f\xac\x02", 4) == 0)
                                pwpa2 = "wpa2-tkip-psk";
                            else
                                pwpa2 = "wpa2-tkip-802.1X";
                        }
                        break;
                    case 0x02:
                        akm_oui = elem_value + 18;
                        if (memcmp(akm_oui, "\x00\x0f\xac\x02", 4) == 0)
                            pwpa2 = "wpa2-tkip-aes-psk";
                        else
                            pwpa2 = "wpa2-tkip-aes-802.1X";
                        break;
                    default:
                        break;
                }
                //WIPSD_DEBUG("=================  ELEMENT_ID_RSN pwpa2=%s ===================\n", pwpa2);
                break;
            }
            default:
                break;
        }

        /* Consume info element */
        remaining_ie_length -= info_element->length;
        /* Go to next IE */
        info_element = (struct ieee80211_ie_header *)(((u8 *) info_element) + sizeof(struct ieee80211_ie_header) + info_element->length);

    }

    if(pwpa)
    {
        strcpy((char *)node->sec_type,pwpa);
        if(pwpa2)
        {
            strcat((char *)node->sec_type,"+");
            strcat((char *)node->sec_type,pwpa2);
        }
    }
    else
    {
        if(pwpa2)
        {
            strcpy((char *)node->sec_type,pwpa2);
        }
    }
    
    node->phy_mode = ieee80211_get_phy_type(rates, xrates, htcap, htinfo, vhtcap, vhtop, node);
    
    return 0;
}
#if 1
int check_relay_unauth_ap(struct w_node * latest,struct w_node * exist)
{
    if (!(latest->node_type & 0x02))
        return 0;

	if(exist->is_arp_added)
	{
		struct w_node_list * tmp = NULL;
		tmp = (w_node_list * )hash_find(wlist_hash_table, (const char *)latest->bssid, 6);
		if ((!tmp) || !(tmp->b_frame.node_type & 0x1))
            return 0;
        
        char *ip=NULL;
        char mac_str[20];
        sprintf(mac_str, MACSTR, MAC2STR(latest->bssid));
        find_lan_ip(mac_str, &ip);
        if(ip)
        {
            clear_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
            XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
            return 0;
        }
        
		if (tmp->b_frame.internal_node != TRUE)
		{
            clear_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
			report_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
            exist->is_arp_added = 0;
		}
	}

    return 0;
}

#endif
int check_ack_hook(struct w_node * latest,struct w_node * exist)
{
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	if(event_count(&exist->ack_c,ack_cmax,
				   &exist->ack_t,ack_tmax )){
		if((exist->node_type & 0x01) > 0)
			report_wips_event(exist, WIPS_EID_ASSO_FLOOD_ACK_STA);
		else if((exist->node_type & 0x02) > 0)
			report_wips_event(exist, WIPS_EID_ASSO_FLOOD_ACK_STA);
	}
	return 0;
}

static int check_ack(unsigned char *buf, int len, struct w_node *wnode_dd)
{
#define D_MAC (4+heardaddr)
	if(len != 10+heardaddr+fcs){
	#if 0
		if(0 && event_count(&w_tmp->ack_c,ack_cmax,
					   &w_tmp->ack_t,ack_tmax )){
			if(fcs ==4){
				w_tmp->rates= (__u16) buf[RATE];
			}else{
				w_tmp->rates= *((__u32 *)(&buf[RATE]));
			}
			if(NOISE){
				w_tmp->noise  = *((int *)(&buf[NOISE]));//-96;//
				w_tmp->signal = *((int *)(&buf[SINGLE]));
			}else{
				w_tmp->noise  = -96;//
				w_tmp->signal = *((int *)(&buf[SINGLE])) - 96;
			}
			w_tmp->channel = *((__u32 *)(&buf[CHANNEL]));
			w_tmp->last_time= fresh_time;//time(&w_tmp->last_time);
			report_wips_event(w_tmp, WIPS_EID_ASSO_FLOOD_ACK_STA);
			/*w_tmp->alert =*/ clear_wevent_bitmap(WIPS_EID_ASSO_FLOOD_ACK_STA, &w_tmp->alert);
		}
	#endif
		return 0;
	}

	memcpy( wnode_dd->mac,&buf[D_MAC],6);
	wnode_dd->refresh_time = fresh_time;

	if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE, check_ack_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}
#undef D_MAC
	return 0;
}

int check_rts_hook(struct w_node * latest,struct w_node * exist)
{

	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	if(event_count(&exist->rts_c,rts_cmax,
				   &exist->rts_t,rts_tmax )){
		if((exist->node_type & 0x01) > 0)
			report_wips_event(exist, WIPS_EID_ASSO_FLOOD_RTS_STA);
		else if((exist->node_type & 0x02) > 0)
			report_wips_event(exist, WIPS_EID_ASSO_FLOOD_RTS_STA);
	}
	return 0;
}

static int check_rts(unsigned char *buf, int len, struct w_node *wnode_dd)
{
#define D_MAC (4+heardaddr)
#define S_MAC (10+heardaddr)
	if(len != 16+heardaddr+fcs)
		return 0;

	memcpy( wnode_dd->mac,&buf[S_MAC],6);
	memcpy( wnode_dd->dstmac,&buf[D_MAC],6);
	wnode_dd->refresh_time = fresh_time;

	if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE, check_rts_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}
#undef D_MAC
#undef S_MAC
	return 0;
}

int check_cts_hook(struct w_node * latest,struct w_node * exist)
{

	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	if(event_count(&exist->cts_c,cts_cmax,
				   &exist->cts_t,cts_tmax )){
		if((exist->node_type & 0x01) > 0)
			report_wips_event(exist, WIPS_EID_ASSO_FLOOD_CTS_STA);
		else if((exist->node_type & 0x02) > 0)
			report_wips_event(exist, WIPS_EID_ASSO_FLOOD_CTS_STA);
	}
	return 0;
}

static int check_cts(unsigned char *buf, int len, struct w_node *wnode_dd)
{
#define D_MAC (4+heardaddr)
	if(len != 10+heardaddr+fcs){
	#if 0
		if(0 && event_count(&w_tmp->cts_c,ack_cmax,
					   &w_tmp->cts_t,ack_tmax )){
			if(fcs ==4){
				w_tmp->rates= (__u16) buf[RATE];
			}else{
				w_tmp->rates= *((__u32 *)(&buf[RATE]));
			}
			if(NOISE){
				w_tmp->noise  = *((int *)(&buf[NOISE]));//-96;//
				w_tmp->signal = *((int *)(&buf[SINGLE]));
			}else{
				w_tmp->noise  = -96;//
				w_tmp->signal = *((int *)(&buf[SINGLE])) - 96;
			}
			w_tmp->channel = *((__u32 *)(&buf[CHANNEL]));
			w_tmp->last_time= fresh_time;//time(&w_tmp->last_time);
			report_wips_event(w_tmp, WIPS_EID_ASSO_FLOOD_CTS_STA);
			/*w_tmp->alert =*/ clear_wevent_bitmap(WIPS_EID_ASSO_FLOOD_CTS_STA, &w_tmp->alert);
		}
	#endif
		return 0;
	}

	memcpy( wnode_dd->mac,&buf[D_MAC],6);
	wnode_dd->refresh_time = fresh_time;

	if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE, check_cts_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}
#undef D_MAC
	return 0;
}

int check_assoc_reassoc_req_hook(struct w_node * latest,struct w_node * exist)
{

	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}


//	memcpy( exist->ipv4,latest->ipv4,16);
	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	exist->capability_info  = latest->capability_info ;
//	exist->last_time		= latest->last_time ;
	exist->node_type		|= latest->node_type;
	exist->interval		 = latest->interval ;
	exist->freq_band		 = latest->freq_band ;

	if(latest->ssid_len > 0 && latest->ssid[0] != '\0'){
	  memcpy( exist->ssid,latest->ssid,SSID_BUFSIZE);
	  exist->ssid_len = latest->ssid_len;
	}

	if(event_count(&exist->assoc_c,assoc_cmax,
				   &exist->assoc_t,assoc_tmax )){
		report_wips_event(exist, WIPS_EID_ASSO_FLOOD_STA);
	}

	if((exist->linked_c == 0xff00) && (exist->auth_c > 0)){
		report_wips_event(exist, WIPS_EID_DEASSO_STA);
	}

	if(exist->interval == 0x00){
		report_wips_event(exist, WIPS_EID_WESSID_NG_STA);
	}else if(exist->interval > 8){
		report_wips_event(exist, WIPS_EID_STA_LISTENINTERVAL_TOOBIG);
	}
	check_lsatpkgtype(latest, exist, WIPS_PKGTYPE_DEFAULT);
	check_address(latest, exist);
	exist->linked_c = 0;
	if(latest->reasso_mark == 1){
		exist->reasso_time = fresh_time;
		exist->reasso_mark = 1;
	}
    
    //check_relay_unauth_ap(exist);
    
	return 0;
}

static int wipsd_check_ieee80211_assoc_reassoc_req(unsigned char *buf, int len, int type, struct w_node *sta_val)
{
#define D_MAC (4+heardaddr)
#define S_MAC (10+heardaddr)
#define BSSIDMAC (16+heardaddr)
#define CAPABILITY_INFO (24+heardaddr)
#define INTERVAL (26+heardaddr)
#define ELEMENT_HD (28+heardaddr)
#define R_ELEMENT_HD (34+heardaddr)

	if(type){
		if(len <= 28+heardaddr+fcs)
			return 0;
	}else{
		if(len <= 34+heardaddr+fcs)
			return 0;
	}

	memcpy( sta_val->dstmac,&buf[D_MAC],6);
	memcpy( sta_val->mac,&buf[S_MAC],6);
	memcpy( sta_val->bssid,&buf[BSSIDMAC],6);
    
	if(type){
        parse_element_tlv(buf + ELEMENT_HD, len - ELEMENT_HD, sta_val);
	}else{
        parse_element_tlv(buf + R_ELEMENT_HD, len - R_ELEMENT_HD, sta_val);
		sta_val->reasso_mark = 1;
	}
    
	sta_val->refresh_time = fresh_time;
	sta_val->last_time= fresh_time;//time(&sta_val.last_time);
	sta_val->interval = *((__u16 *)(&buf[INTERVAL]));
	swap16(sta_val->interval);
	sta_val->capability_info = *((__u16 *)(&buf[CAPABILITY_INFO]));
	swap16(sta_val->capability_info);
	sta_val->node_type = 0x12;

#ifdef X86_FINDIP
	char mac_str[20];
	char *ip;

    sprintf(mac_str, NMACQUAD_FMT,NMACQUAD(sta_val->mac));

	find_lan_ip(mac_str, &ip);
	if(ip != NULL) {
		strcpy( sta_val->ipv4, (char *)ip);
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
	}
#endif
send_ap_info(sta_val,"wipsd_check_ieee80211_assoc_reassoc_req");

	if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2STALIST, check_assoc_reassoc_req_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}

#undef D_MAC
#undef S_MAC
#undef BSSIDMAC
#undef CAPABILITY_INFO
#undef INTERVAL
#undef ELEMENT_HD
#undef R_ELEMENT_HD
	return 0;
}
/*
static int check_assoc_reassoc_resp_hook(struct w_node * latest,struct w_node * exist)
{

}
*/

int check_assoc_reassoc_resp_hook(struct w_node * latest,struct w_node * exist)
{
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	switch(latest->reason_code){
		case 12:
		case 17:
		case 18:
		case 19:
		case 20:
		case 21:
		case 22:
		case 23:
		case 24:
		case 25:
		case 26:
			report_wips_event(exist, WIPS_EID_ASSO_DENIED_STA);
			break;
		default :
			clear_wips_event(exist, WIPS_EID_ASSO_DENIED_STA);
			break;
	}
	check_address(latest, exist);
	return 0;
}

static int check_assoc_reassoc_resp(unsigned char *buf, int len, int type)
{
#define D_MAC (4+heardaddr)
#define S_MAC (10+heardaddr)
#define BSSIDMAC (16+heardaddr)
#define STATUS_CODE (26+heardaddr)
	if(len < 30+heardaddr+fcs)
		return 0;

	struct w_node wnode_dd;
	memset(&wnode_dd,0,sizeof(wnode_dd));
	memcpy( wnode_dd.mac,&buf[D_MAC],6);
	memcpy( wnode_dd.dstmac,&buf[S_MAC],6);
	memcpy( wnode_dd.bssid,&buf[BSSIDMAC],6);
	wnode_dd.reason_code = *((__u16 *)(&buf[STATUS_CODE]));
	swap16(wnode_dd.reason_code);
	wnode_dd.refresh_time = fresh_time;

	if(find_wlistnode_sniffer(&wnode_dd, NO_ADD_NODE, check_assoc_reassoc_resp_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}

#undef D_MAC
#undef S_MAC
#undef BSSIDMAC
#undef STATUS_CODE
	return 0;
}

int check_probe_req_hook(struct w_node * latest,struct w_node * exist)
{
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

//	memcpy( exist->ipv4,latest->ipv4,16);
	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
//	exist->last_time		= latest->last_time ;
	exist->node_type		= exist->node_type | 0x02;
	exist->sequence_num		= latest->sequence_num ;
	exist->freq_band		 = latest->freq_band ;
	if(0 && latest->ssid_len > 0 && latest->ssid[0] != '\0'){
		if(exist->linked_c == 0xff00){
			if(memcmp( latest->bssid,exist->bssid,6) == 0){
				memcpy( exist->ssid,latest->ssid,SSID_BUFSIZE);
			}
		}
	}
	if(latest->probe_ssid[0]){
		exist->probe_req_time = fresh_time;
		exist->probe_req_mark = 1;
		memcpy( exist->probe_ssid, latest->probe_ssid,SSID_BUFSIZE_D);
	}
	if(memcmp( exist->bssid,latest->pro_bssid,6) != 0){
		memcpy( exist->pro_bssid, latest->pro_bssid,6);
		exist->probe_noauth_mark = 1;
		exist->probe_noauth_time = fresh_time;
	}

	if(event_count(&exist->prob_req_c,15,
				   &exist->prob_req_t,prob_req_tmax )){
		nodeInfo * tmp=NULL;
		tmp = (nodeInfo * )hash_find(nodeinfo_hash_table,
				(const char *)latest->mac, 6);
		if((!tmp) || ( !(tmp->node_type & 0x40))){
			//WIPSD_DEBUG("WIPS_EID_UNAUTHSTA_PROBE_TOOMANY\n");
			report_wips_event(exist, WIPS_EID_UNAUTHSTA_PROBE_TOOMANY);
		}
	}
	exist->prob_req_c--;
	if(event_count(&exist->prob_req_c,prob_req_cmax,
				   &exist->prob_req_t,prob_req_tmax )){
		report_wips_event(exist, WIPS_EID_PROBE_FLOOD_STA);
	}

#if 0
    if((exist->node_type & 0x01) && (exist->node_type & 0x02) && (memcmp(exist->mac, exist->bssid, 6) == 0))
    {
        //WIPSD_DEBUG("----------WIPS_EID_STA_PROXY_AP----mac="NMACQUAD_FMT"---bssid="NMACQUAD_FMT"-------%s-%d:exist->node_type=%#02x\n", 
        // NMACQUAD(exist->mac), NMACQUAD(exist->bssid), __func__, __LINE__, exist->node_type);
        report_wips_event(exist, WIPS_EID_STA_PROXY_AP);
        clear_wips_event(exist, WIPS_EID_STA_PROXY_AP);
    }
#endif


	if(0 && (exist->node_type & 0x40) == 0x40) {
		report_wips_event(exist, WIPS_EID_VIOLENT_CRACK_STA);
		exist->auth_c_crack = 0;
		exist->deauth_c_crack = 0;
	}

	check_signal(latest,exist);
	check_address(latest, exist);
    //check_relay_unauth_ap(exist);
    
	return 0;
}

static int check_probe_req(unsigned char *buf, int len, struct w_node *sta_val)
{

#define D_MAC (4+heardaddr)
#define S_MAC (10+heardaddr)
#define BSSIDMAC (16+heardaddr)
#define SEQ_CTL (22+heardaddr)
#define ELEMENT_HD (24+heardaddr)

	if(len <= 26+heardaddr+fcs)
		return 0;

	memcpy( sta_val->dstmac, &buf[D_MAC], 6);
	memcpy( sta_val->mac,&buf[S_MAC],6);
	memcpy( sta_val->pro_bssid,&buf[BSSIDMAC],6);

	sta_val->refresh_time = fresh_time;
	sta_val->last_time= fresh_time;//time(&sta_val.last_time);
	sta_val->node_type = 0x12;
	sta_val->sequence_num = *((__u16 *)(&buf[SEQ_CTL]));
	swap16(sta_val->sequence_num);
    
    //WIPSD_DEBUG("%s-%d:mac="NMACQUAD_FMT"  bssid="NMACQUAD_FMT"\n", __func__, __LINE__, NMACQUAD(sta_val->mac), NMACQUAD(sta_val->bssid));
    parse_element_tlv(buf + ELEMENT_HD, len - ELEMENT_HD, sta_val);

    if (sta_val->ssid_len)
    {
        strlcpy(sta_val->probe_ssid, sta_val->ssid, sizeof(sta_val->probe_ssid));
        memset(sta_val->ssid, 0, sizeof(sta_val->ssid));
    }
#ifdef X86_FINDIP
	char mac_str[20];
	char *ip;

    sprintf(mac_str, NMACQUAD_FMT,NMACQUAD(sta_val->mac));

	 find_lan_ip(mac_str, &ip);
	if(ip != NULL){
		strcpy( sta_val->ipv4, (char *)ip);
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
	}
#endif
	send_ap_info(sta_val,"check_probe_req");

	if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2STALIST, check_probe_req_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}

#undef D_MAC
#undef S_MAC
#undef BSSIDMAC
#undef SEQ_CTL
#undef ELEMENT_HD
	return 0;
}

int check_probe_resp_hook(struct w_node * latest,struct w_node * exist)
{
	static int cou =0;
	static int tim =0;
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	exist->rates			= latest->rates ;
	exist->signal		   = latest->signal ;
	exist->noise			= latest->noise ;
	if(latest->node_type == 2){
		if(memcmp( exist->probe_ssid,latest->ssid,SSID_BUFSIZE_D) == 0){
			exist->probe_req_mark |= 2;
		}
		return 0;
	}
	exist->capability_info  = latest->capability_info ;
	exist->interval		 = latest->interval ;
	exist->node_type		|= latest->node_type;
	if(fcflags & 0x08){}else{
		if( exist->timestamp == latest->timestamp ){
			if(event_count(&cou,2,&tim,5 ))
				report_wips_event(exist, WIPS_EID_AIRBASE_NG_FAKE_AP);
		}else{
			exist->timestamp = latest->timestamp;
			clear_wips_event(exist, WIPS_EID_AIRBASE_NG_FAKE_AP);
		}
	}
	if((exist->node_type & 0x04) == 0x04){
		report_wips_event(exist, WIPS_EID_AD_HOC);
	}
	if(latest->ssid_len == 0){
	}else{
		if(exist->hide_ssid == TRUE){
#if 0
			memcpy( exist->ssid,"hiding(",7);
			memcpy( &(exist->ssid[7]),latest->ssid,SSID_BUFSIZE-7);
			if(latest->ssid_len >= SSID_BUFSIZE-9){
				exist->ssid[SSID_BUFSIZE-2]=')';
				exist->ssid[SSID_BUFSIZE-1]='\0';
			}else{
				exist->ssid[latest->ssid_len+7]=')';
				exist->ssid[latest->ssid_len+8]='\0';
			}
#else
			memcpy( exist->ssid,latest->ssid,SSID_BUFSIZE);
			if(latest->ssid_len >= SSID_BUFSIZE-9){
				memcpy( &(exist->ssid[SSID_BUFSIZE-9]),"(hiding)",8);
				exist->ssid[SSID_BUFSIZE-1]='\0';
			}else{
				memcpy( &(exist->ssid[latest->ssid_len]),"(hiding)",8);
				exist->ssid[latest->ssid_len+8]='\0';
			}
#endif
		}else{
			memcpy( exist->ssid,latest->ssid,SSID_BUFSIZE);
		}
		exist->ssid_len = latest->ssid_len;
	}

	check_signal(latest,exist);
	check_address(latest, exist);
    //check_relay_unauth_ap(exist);
    
	return 0;
}

static int check_probe_resp(unsigned char *buf, int len, struct w_node *beacon_val)
{
#define D_MAC (4+heardaddr)
#define MACADD (16+heardaddr)
#define SAMAC (10+heardaddr)
#define HD_LEN (24+heardaddr)
#define INTERVAL (32+heardaddr)
#define CAPABILITY (34+heardaddr)
#define ELEMENT_HD (36+heardaddr)

	memcpy( beacon_val->dstmac,&buf[D_MAC],6);
	memcpy( &beacon_val->mac, &buf[SAMAC], 6);
	memcpy( &beacon_val->bssid, &buf[MACADD], 6);
	if(memcmp( beacon_val->mac,beacon_val->bssid,6) != 0){
		goto out;
	}

	//get interval
	beacon_val->interval = *((__u16 *)(&buf[INTERVAL]));
	swap16(beacon_val->interval);
	beacon_val->timestamp= *((uint64_t *)(&buf[HD_LEN]));
	swap64(beacon_val->timestamp);
	beacon_val->refresh_time = fresh_time;
	beacon_val->capability_info = *((__u16 *)(&buf[CAPABILITY]));
	swap16(beacon_val->capability_info);
	beacon_val->node_type = 0x01;
    
    //WIPSD_DEBUG("%s-%d:mac="NMACQUAD_FMT"  bssid="NMACQUAD_FMT"\n", __func__, __LINE__, NMACQUAD(beacon_val->mac), NMACQUAD(beacon_val->bssid));
	parse_element_tlv(buf + ELEMENT_HD, len - ELEMENT_HD, beacon_val);

	if(beacon_val->capability_info & 0x02){
		beacon_val->node_type = 0x04;
		if(find_wlistnode_sniffer(beacon_val, NO_ADD_NODE, check_probe_resp_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}
	}else{
		if(find_wlistnode_sniffer(beacon_val, NO_ADD_NODE, check_probe_resp_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}
	}
	memcpy( beacon_val->mac,beacon_val->dstmac,6);
	beacon_val->node_type = 2;
	if(find_wlistnode_sniffer(beacon_val, LIST_TASK_ADD2STALIST, check_probe_resp_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}

out:

#undef MACADD
#undef SAMAC
#undef HD_LEN
#undef INTERVAL
#undef CAPABILITY
#undef D_MAC
#undef ELEMENT_HD
	return 0;
}

int check_beacon_hook(struct w_node * latest,struct w_node * exist)
{

	memcpy( exist->sec_type,latest->sec_type,40);
	if(memcmp( exist->bssid,latest->bssid,6)!=0){
		memset( exist->gatemac,0,6);
		memset( exist->addr_ipv4,0,4);
		memcpy( exist->bssid,latest->bssid,6);
	}
//	if(0)check_beacon_ssid(latest, exist);
	if(latest->ssid_len > 0 && latest->ssid[0] != '\0'){
		if(memcmp( exist->ssid,latest->ssid,SSID_BUFSIZE) != 0){
	//		node_changed(exist, LIST_TASK_TREE_AP_SSID_CHANGE);
			memcpy( exist->ssid,latest->ssid,SSID_BUFSIZE);
		}
		exist->ssid_len	 = latest->ssid_len;
		exist->hide_ssid	= FALSE;
		report_wips_event(exist, WIPS_EID_AP_BRAODCAST_SSID);
	}else{
		exist->hide_ssid	= TRUE;
	}
	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
/*	if(exist->channel != latest->channel && latest->channel > 0){
		node_changed(exist, LIST_TASK_TREE_AP_CHANNEL_CHANGE);
		exist->channel		  = latest->channel ;
	}*/
	exist->channel		  = latest->channel ;
	exist->rates			= latest->rates ;
	exist->signal		   = latest->signal ;
	exist->noise			= latest->noise ;
	exist->capability_info  = latest->capability_info ;
	exist->interval		 = latest->interval ;
	exist->b_rates		  = latest->b_rates;
	exist->g_rates		  = latest->g_rates;
	exist->n_rates		  = latest->n_rates;
    exist->phy_mode = latest->phy_mode;
//	exist->last_time		= latest->last_time ;
	if(latest->node_type == 1)exist->node_type		= exist->node_type | 0x01;
	exist->node_type		|= latest->node_type;
	exist->sequence_num		= latest->sequence_num ;
	exist->freq_band		 = latest->freq_band ;
	if((exist->node_type & 0x04) && !(latest->node_type & 0x04)){
		exist->node_type		&= ~0x04;
	}
	exist->beacon_c++;

	if(check_internal_essid_from_wnet(exist->ssid) < 0){
		report_wips_event(exist, WIPS_EID_UNAUTH_AP);
	}else if(exist->ipv4[0] != '\0'){
		check_auth_device(latest, exist);
	}
    #if 1
	if(1){
//		int ssid_type =0;
		nodeInfo * tmp=NULL;
		tmp = (nodeInfo * )hash_find(nodeinfo_hash_table,
				(const char *)exist->mac, 6);
		if(tmp){
			int node_type = tmp->node_type & 0x180;
			if(node_type == 0){//ext
				exist->internal_node = FALSE;
				exist->ipv4[0] = '\0';
				clear_wips_event(exist, WIPS_EID_UNAUTH_AP);
			}else if(node_type == 0x80){//in
				exist->internal_node = TRUE;
				if(tmp->ipv4[0] != '\0'){
					strncpy( exist->ipv4,tmp->ipv4,sizeof(exist->ipv4));
				}
				clear_wips_event(exist, WIPS_EID_UNAUTH_AP);
			}else{//rogue
				exist->internal_node = FALSE;
				exist->ipv4[0] = '\0';
				report_wips_event(exist, WIPS_EID_UNAUTH_AP);
			}
			strncpy( exist->name,tmp->name,sizeof(exist->name));
		}
	//	else if((ssid_type = find_internal_ssid(exist->ssid)) > 0){
	//		exist->internal_node = TRUE;
	//		if( exist->ipv4[0] == '\0'){
	//			memset(exist->ipv4, 0, sizeof(exist->ipv4));
	//			memcpy( exist->ipv4,"    ",4);
	//		}
	//	}
	}
#endif
	// Check for the network name is the list of hotspots
	if (lookup_hotspot(exist->ssid) == 0)
	{
		report_wips_event(exist, WIPS_EID_HOTSPOTTER_AP);
	}
	else {
		clear_wips_event(exist, WIPS_EID_HOTSPOTTER_AP);
	}

	if(strcmp(exist->sec_type,"open-system")==0)
		report_wips_event(exist, WIPS_EID_NO_CRYPT_AP);
	else if(strcmp(exist->sec_type,"wep")==0)
		report_wips_event(exist, WIPS_EID_CRYPT_WEP_AP);
	else {
		clear_wips_event(exist, WIPS_EID_NO_CRYPT_AP);
		clear_wips_event(exist, WIPS_EID_CRYPT_WEP_AP);
		}
#if 0
	if((exist->node_type & 0x01) && (exist->node_type & 0x02) && (memcmp(exist->mac, exist->bssid, 6) == 0))
    {
        //WIPSD_DEBUG("----------WIPS_EID_STA_PROXY_AP----mac="NMACQUAD_FMT"---bssid="NMACQUAD_FMT"-------%s-%d:exist->node_type=%#02x\n", 
        // NMACQUAD(exist->mac), NMACQUAD(exist->bssid), __func__, __LINE__, exist->node_type);
		report_wips_event(exist, WIPS_EID_STA_PROXY_AP);
        clear_wips_event(exist, WIPS_EID_STA_PROXY_AP);
	}
#endif
	if( (exist->node_type & 0x20) == 0x20){
		report_wips_event(exist, WIPS_EID_WPS_AP/*WPS ACTION*/);
	}
	else
		clear_wips_event(exist, WIPS_EID_WPS_AP);

	if((exist->node_type & 0x08) == 0x08){
		report_wips_event(exist, WIPS_EID_WDS_AP);
	}
	else
		clear_wips_event(exist, WIPS_EID_WDS_AP);

	if(exist->mac[0]==0x1a && !(exist->node_type & 0x80)){
		struct list_tast *mp=NULL;
		mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
		if(mp == NULL){
			WIPSD_DEBUG("malloc for new list_task err!\n");
		}else{
			memset(mp,0,sizeof(struct list_tast));
			mp->task_type= LIST_TASK_APSTA;
			mp->node= (void *)exist;
			insertListTask(mp);
		}
	}

	if((exist->node_type & 0x04) == 0x04){
		report_wips_event(exist, WIPS_EID_AD_HOC);
	}
	if(event_count(&exist->beaconc_c,50,
				   &exist->beaconc_t,5 )){
		report_wips_event(exist, WIPS_EID_TOOMANY_BEACON);
	}
	check_address(latest, exist);
	if(latest->n_rates){
		report_wips_event(exist, WIPS_EID_11N_DEVICE);
	}
	exist->open_qos = latest->open_qos;
	if(latest->open_qos != 1){
		report_wips_event(exist, WIPS_EID_NO_QOS);
	}
	if(latest->node_type == 0x01 && (exist->timestamp > latest->timestamp)){
		report_wips_event(exist, WIPS_EID_AP_REBOOTED);
	}
	exist->timestamp = latest->timestamp;

	exist->signal_cum += latest->signal;
	exist->signal_con++;
	exist->signal_average = exist->signal_cum / exist->signal_con;
	if(exist->signal_average < -95){
		report_wips_event(exist, WIPS_EID_AP_SIGNAL_TOOLOW);
	}else if(exist->signal_average > 0){
		report_wips_event(exist, WIPS_EID_AP_SIGNAL_TOOHIGH);
	}
	if(latest->n_20and40){
		report_wips_event(exist, WIPS_EID_AP_SUPPORT40MHZ);
	}
	if((exist->g_rates && exist->b_rates) || latest->capability_info & 0x0400){
		report_wips_event(exist, WIPS_EID_AP_BG_MODE);
	}
	check_channel_blacklist(latest, exist,0, 0, 0);
	if(0 && check_unauth_essid(exist)){
		report_wips_event(exist, WIPS_EID_UNAUTH_ESSID);
	}
	if(exist->g_rates && exist->n_rates){
		report_wips_event(exist, WIPS_EID_AP_GN_MODE);
	}

	return 0;
}

static int check_beacon(unsigned char *buf, int len, struct w_node *beacon_val)
{
#define D_MAC (4+heardaddr)
#define MACADD (16+heardaddr)
#define SAMAC (10+heardaddr)
#define SEQ_CTL (22+heardaddr)
#define HD_LEN (24+heardaddr)
#define INTERVAL (32+heardaddr)
#define CAPABILITY (34+heardaddr)
#define ELEMENT_HD (36+heardaddr)

	if(buf[2+heardaddr] ==0 &&
	   buf[3+heardaddr] ==0 &&
	   memcmp(&buf[len-fcs-6], MDK3_BEACON, 6) == 0){
		static __u32 num =300;
		if(num > 200){
			num = 0;
			w_tmp->rates = beacon_val->rates;
			w_tmp->noise =	beacon_val->noise;
			w_tmp->signal = beacon_val->signal;
			w_tmp->channel = beacon_val->channel;
			memcpy( w_tmp->mac,&buf[SAMAC],6);
			memcpy( w_tmp->bssid,&buf[MACADD],6);
			w_tmp->last_time= fresh_time;//time(&w_tmp->last_time);
			w_tmp->node_type = 0x01;
			report_wips_event(w_tmp, WIPS_EID_MDK3_BEACON_FLOOD_AP);
			memset(w_tmp,0,sizeof(struct w_node));
			return 0;
		}else{
			num++;
			return 0;
		}
	}

	memcpy( &beacon_val->dstmac, &buf[D_MAC], 6);
	memcpy( &beacon_val->mac, &buf[SAMAC], 6);
	memcpy( &beacon_val->bssid, &buf[MACADD], 6);

	beacon_val->sequence_num = *((__u16 *)(&buf[SEQ_CTL]));
	swap16(beacon_val->sequence_num);
	beacon_val->timestamp= *((uint64_t *)(&buf[HD_LEN]));
	swap64(beacon_val->timestamp);
	beacon_val->interval = *((__u16 *)(&buf[INTERVAL]));
	swap16(beacon_val->interval);
	beacon_val->capability_info = *((__u16 *)(&buf[CAPABILITY]));
	swap16(beacon_val->capability_info);
    
	if((memcmp( beacon_val->mac, beacon_val->bssid,6) != 0)
		|| (memcmp( beacon_val->mac,"\x00\x00\x00\x00\x00\x00",6) == 0)){
		if(!(beacon_val->capability_info & 0x02 )) goto out;
	}
    
	beacon_val->refresh_time = fresh_time;
	beacon_val->last_time= fresh_time;//time(&beacon_val.last_time);
	beacon_val->ssid1_AgingTime = fresh_time;
    
	if(buf[CAPABILITY]& 0x10){
		strcpy(beacon_val->sec_type,"wep");//
	}else{
		strcpy(beacon_val->sec_type,"open-system");//
	}

    //WIPSD_DEBUG("%s-%d:mac="NMACQUAD_FMT"  bssid="NMACQUAD_FMT"\n", __func__, __LINE__, NMACQUAD(beacon_val->mac), NMACQUAD(beacon_val->bssid));
	parse_element_tlv(buf + ELEMENT_HD, len - ELEMENT_HD, beacon_val);

#ifdef X86_FINDIP
	char *ip;
	char mac_str[20];

    sprintf(mac_str, NMACQUAD_FMT,NMACQUAD(beacon_val->mac));

	find_lan_ip(mac_str, &ip);
	if(ip) {
		strncpy( beacon_val->ipv4, (char * )ip,15);
		beacon_val.internal_node = 1;
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
	}
#endif
    send_ap_info(beacon_val,"check_beacon");

	switch(beacon_val->capability_info & 3){
		case 1:
            beacon_val->node_type = 0x01;
			if(find_wlistnode_sniffer(beacon_val, LIST_TASK_ADD2APLIST, check_beacon_hook)!=0){
				WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
			}
			break;
		case 2:
            beacon_val->node_type = 0x14;
            WIPSD_DEBUG("%s-%d:beacon add 2 sta list\n", __func__, __LINE__);
			if(find_wlistnode_sniffer(beacon_val, LIST_TASK_ADD2STALIST, check_beacon_hook)!=0){
				WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
			}
			break;
		default :
			break;
	}

	static int flag_toomanyap =0;
	if(debug_ap_number > 150){
		if(flag_toomanyap ==0){
			flag_toomanyap = 1;
			memset(w_tmp, 0, sizeof(struct w_node));
			w_tmp->node_type = 0x02;
			report_wips_event(w_tmp, WIPS_EID_TOOMANY_AP);
		}
	}else if(flag_toomanyap ==1){
		flag_toomanyap =0;
	}

out:
#undef D_MAC
#undef MACADD
#undef SAMAC
#undef SEQ_CTL
#undef HD_LEN
#undef INTERVAL
#undef CAPABILITY
#undef ELEMENT_HD
	return 0;
}

/*  it's useless.
static void check_atim(unsigned char *buf, int len)
{
}*/

int check_data_hook(struct w_node * latest,struct w_node * exist)
{
	int ret = FALSE;
	struct w_node *node = NULL;

	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	exist->freq_band		 = latest->freq_band ;
	exist->signal		   = latest->signal ;
	exist->noise			= latest->noise ;
	exist->last_time		= latest->last_time ;
	memcpy(exist->addr_ipv4, latest->addr_ipv4, 4);
    exist->node_type |= latest->node_type;
    if (latest->node_type & 0x2)
        exist->is_assoc2ap = latest->is_assoc2ap;

	exist->dataframe_count++;
	if( memcmp(latest->gatemac, "\x00\x00\x00\x00\x00\x00", 6)!=0 &&
	    (latest->gatemac[0]&0x1)==0){
		memcpy(exist->gatemac, latest->gatemac, 6);
		memcpy(exist->bssid, latest->bssid, 6);
	}

	if((latest->link_changed == 1) && (exist->node_type & 0x10) == 0x10)
		exist->link_changed = 1;
#if 0
	if( ((latest->dstmac[0] & 0x01) == 0)
		&& (memcmp(latest->dstmac, "\x00\x00\x00\x00\x00\x00", 6)!=0)){
		memcpy(exist->dstmac, latest->dstmac, 6);
		strncpy(exist->ipv4, latest->ipv4, sizeof(latest->ipv4));
	}
#endif


	if(latest->node_type & 0x01){
//		check_wireless_object(latest,exist);

		if(check_unworktime_essid_from_wnet(exist->ssid)){
			set_wevent_bitmap(WIPS_EID_WIRELESS_MOOCH, &latest->alert);
		}
	}else{
	#if 0
		if(latest->internal_node == TRUE){
			exist->internal_node = TRUE;
			if(exist->ipv4[0] == '\0')
				memcpy( exist->ipv4,latest->ipv4,sizeof(exist->ipv4));
		}
		#endif
	}

	exist->data_mum += latest->data_mum;
	check_bitrate_blacklist(latest, exist,0, 0, 0);
	if(test_wevent_bitmap(WIPS_EID_STA_SMALL_FRAG_PKG, &latest->alert)) {
		report_wips_event(exist, WIPS_EID_STA_SMALL_FRAG_PKG);
	}else if(test_wevent_bitmap(WIPS_EID_AP_SMALL_FRAG_PKG, &latest->alert)
		&& exist->node_type & 0x01) {
		report_wips_event(exist, WIPS_EID_AP_SMALL_FRAG_PKG);
	}
	if(test_wevent_bitmap(WIPS_EID_STA_TOOMANY_RETRY, &latest->alert)) {
		if(event_count(&exist->retry_c,100,
				   &exist->retry_t,5 )){
			report_wips_event(exist, WIPS_EID_STA_TOOMANY_RETRY);
		}
	}else if(test_wevent_bitmap(WIPS_EID_AP_TOOMANY_RETRY, &latest->alert)
		&& exist->node_type & 0x01) {
		if(event_count(&exist->retry_c,100,
				   &exist->retry_t,5 )){
			report_wips_event(exist, WIPS_EID_AP_TOOMANY_RETRY);
		}
	}

	if(latest->wpa8021x_mark & 1){
		exist->wpa8021x_mark = 1;
		exist->wpa_time = fresh_time;
		if(latest->wpa8021x_mark & 2 &&
			event_count(&exist->auth8021X_c,5,
					   &exist->auth8021X_t,5 )){
			report_wips_event(exist, WIPS_EID_8021XAUTH_ATTACK);
		}
	}else if(exist->linked_c != 0xff00){
		if(event_count(&exist->linked_c,2,
					   &exist->linked_t,5 )){
			exist->linked_c = 0xff00;
		}
	}

	if(latest->channel != exist->data_channel
		&& latest->net_type!=NET_TYPE_8021X) {

		exist->channel_changed	=	1;
//		exist->channel		= latest->channel ;
		exist->data_channel 	= latest->channel ;
	}
/*
	if((latest->node_type & 1 ) && ((latest->node_type & 0x04) != 0x04)){
		goto out;
	}
*/
	if(latest->rates){
		if(exist->rates != latest->rates){
			if(event_count(&exist->rate_change,20,
						   &exist->rate_times,5 )){
				report_wips_event(exist, WIPS_EID_RATESWITCH_TOOFAST);
			}
		}
		exist->rates = latest->rates ;
	}

	if((exist->node_type & 0x06)
	   && !latest->is_null_data/*not null data*/
	   && latest->net_type!=NET_TYPE_8021X){
		nodeInfo * tmp=NULL;
		tmp = (nodeInfo * )hash_find(nodeinfo_hash_table,
				(const char *)latest->mac, 6);
		if(tmp){
			strncpy(exist->name, tmp->name, sizeof(exist->name));
		}
		if(0 == get_wlist_node((char *)latest->bssid, &node)){
			ret = TRUE;
			if(strncmp( exist->ssid, node->ssid, sizeof(exist->ssid)) != 0
			   && !latest->is_null_data/*not null data*/
			   && latest->net_type!=NET_TYPE_8021X){//ssid
				node_changed(exist, LIST_TASK_TREE_STA_BSSID_CHANGE);
				exist->linked_c = 0;
				exist->linked_t = latest->refresh_time;
				exist->link_changed = 1;
				exist->block_func	= 0;	//changed for sap
				exist->channel		  = node->channel ;
				exist->data_channel	  = 0;
				memset(exist->addr_ipv4, 0, 4);
				memset(exist->gatemac, 0, 6);
				if(exist->ssid[0]!='\0'&&node->ssid[0]!='\0'){
					memcpy( exist->bssid,latest->bssid,6);
					strncpy( exist->ssid, node->ssid, sizeof(exist->ssid));
					clear_wips_event(exist, WIPS_EID_SWITCH_ESSID);
					report_wips_event(exist, WIPS_EID_SWITCH_ESSID);
					clear_wips_event(exist, WIPS_EID_STA_ON_NETWORK);
				}else{
					memcpy( exist->bssid,latest->bssid,6);
					strncpy( exist->ssid, node->ssid, sizeof(exist->ssid));
				}
				report_wips_event(exist, WIPS_EID_STA_ON_NETWORK);
				clear_wips_event(exist, WIPS_EID_STA_OFF_NETWORK);
			}else if(memcmp( exist->bssid,latest->bssid,6) != 0
			   //del 20150211 && !latest->is_null_data/*not null data*/
   			   && latest->net_type!=NET_TYPE_8021X){//bssid
				node_changed(exist, LIST_TASK_TREE_STA_BSSID_CHANGE);
				memcpy( exist->bssid,latest->bssid,6);
				strncpy( exist->ssid, node->ssid, sizeof(exist->ssid));
				exist->linked_c = 0;
				exist->linked_t = latest->refresh_time;
				exist->link_changed = 1;
				exist->block_func	= 0;
				exist->channel		  = node->channel ;
				exist->data_channel	  = 0;
				memset(exist->addr_ipv4, 0, 4);
				memset(exist->gatemac, 0, 6);
				clear_wips_event(exist, WIPS_EID_SWITCH_BSSID);
				report_wips_event(exist, WIPS_EID_SWITCH_BSSID);
			}else{
				if(node->channel != exist->channel){
					exist->channel_changed	=	1;
					exist->channel		= node->channel ;
				}
			}
		}
	}

/*	if(latest->net_type!=NET_TYPE_8021X){
		exist->data_channel	=	latest->channel;
	}*/

	if(0 && latest->sequence_num > 0){
		exist->sequence_num = latest->sequence_num;
	}

	if((exist->node_type & 0x04) == 0x04)
		report_wips_event(exist, WIPS_EID_AD_PKG);
	else
		clear_wips_event(exist, WIPS_EID_AD_PKG);

	if(latest->duration > 1000){
		report_wips_event(exist, WIPS_EID_DURATION_ATTACK);
	}
	else
		clear_wips_event(exist, WIPS_EID_DURATION_ATTACK);

	if(exist->node_type & 0x02){
		if((exist->node_type & 0x08) == 0x08){
			report_wips_event(exist, WIPS_EID_WDS_STA);
		}
		else
			clear_wips_event(exist, WIPS_EID_WDS_STA);
	}

	if(0 && (exist->node_type & 0x40) == 0x40) {
		report_wips_event(exist, WIPS_EID_VIOLENT_CRACK_STA);
		exist->auth_c_crack = 0;
		exist->deauth_c_crack = 0;
	}

	if(test_wevent_bitmap(WIPS_EID_AIREPLAY_NG_FRAMG_STA, &latest->alert)) {
		report_wips_event(exist, WIPS_EID_AIREPLAY_NG_FRAMG_STA);
	}
	if(test_wevent_bitmap(WIPS_EID_AIREPLAY_NG_CHOP_STA, &latest->alert)) {
		report_wips_event(exist, WIPS_EID_AIREPLAY_NG_CHOP_STA);
	}
	if(test_wevent_bitmap(WIPS_EID_AIREPLAY_NG_ARP_STA, &latest->alert)) {
		if(event_count(&exist->arp_c,arp_cmax,
				   &exist->arp_t,arp_tmax )){
			report_wips_event(exist, WIPS_EID_AIREPLAY_NG_ARP_STA);
		}
	}
	if(test_wevent_bitmap(WIPS_EID_BRAODCAST_STORM, &latest->alert)) {
		check_braodcast_storm(latest, exist);
	}

	check_signal(latest,exist);
	check_bitrate(latest,exist);
	check_lsatpkgtype(latest, exist, WIPS_PKGTYPE_DATA);
	check_address(latest, exist);
	if(1){
#if 1
		if (!node){
			if(0 == get_wlist_node((char *)latest->bssid, &node)){
				if(memcmp( exist->bssid,latest->bssid,6) != 0){//bssid
					ret = TRUE;
					node_changed(exist, LIST_TASK_TREE_STA_BSSID_CHANGE);
					memcpy( exist->bssid,latest->bssid,6);
					strncpy( exist->ssid, node->ssid, sizeof(exist->ssid));
					exist->linked_c = 0;
					exist->linked_t = latest->refresh_time;
					exist->link_changed = 1;
					exist->block_func	= 0;
					exist->channel		  = node->channel ;
					exist->data_channel	  = 0;
					memset(exist->addr_ipv4, 0, 4);
					memset(exist->gatemac, 0, 6);
					clear_wips_event(exist, WIPS_EID_SWITCH_BSSID);
					report_wips_event(exist, WIPS_EID_SWITCH_BSSID);
				}
			}
		}
#endif

		struct w_node *__node = NULL;
		if (!(latest->dstmac[0] & 0x01)){
			if(0 == get_wlist_node((char *)latest->dstmac, &__node)){
				//exist->channel		  = __node->channel ;
				if((__node->node_type & 0x02) && !(__node->node_type & 0x05)
					&& memcmp( exist->bssid,__node->bssid,6) == 0){
					report_wips_event(exist, WIPS_EID_CLOSE_PSPE);
				}
			}
		}
	}
	exist->signal_cum += latest->signal;
	exist->signal_con++;
	exist->signal_average = exist->signal_cum / exist->signal_con;
	if(exist->signal_average < -95){
		report_wips_event(exist, WIPS_EID_STA_SIGNAL_TOOLOW);
	}else if(exist->signal_average > 0){
		report_wips_event(exist, WIPS_EID_STA_SIGNAL_TOOHIGH);
	}
    
	check_auth_device(latest, exist);

    check_relay_unauth_ap(latest, exist);

	if(test_wevent_bitmap(WIPS_EID_WIRELESS_MOOCH, &latest->alert)
		|| working_time_check()){
		report_wips_event(exist, WIPS_EID_WIRELESS_MOOCH);
	}

	if(ret == TRUE){
		sta_walk_wpolicy(exist, node);
	}else{
		sta_walk_wpolicy(exist, NULL);
	}
//out:
	return 0;
}


int check_wdsdata_hook(struct w_node * latest,struct w_node * exist)
{
	if(memcmp( exist->bssid,latest->bssid,6) != 0
	   && !latest->is_null_data/*not null data*/
 	   && latest->net_type!=NET_TYPE_8021X){
		memset( exist->gatemac,0,6);
		memset( exist->addr_ipv4,0,4);
		memcpy( exist->bssid,latest->bssid,6);
		exist->linked_c = 0;
		exist->linked_t = latest->refresh_time;

		struct w_node *node;
		if(0 == get_wlist_node((char *)latest->bssid, &node)){
			exist->channel		  = node->channel ;
		}
	}
	if(latest->net_type!=NET_TYPE_8021X){
		exist->data_channel	=	latest->channel;
	}
//	memcpy( exist->ipv4,latest->ipv4,16);
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	if(latest->rates) exist->rates = latest->rates ;
	exist->signal		   = latest->signal ;
	exist->noise			= latest->noise ;
//	exist->last_time		= latest->last_time ;
	exist->node_type		= exist->node_type | 0x08;
	exist->freq_band		 = latest->freq_band ;
	memcpy(exist->addr_ipv4, latest->addr_ipv4, 4);
	exist->dataframe_count++;
	if( memcmp(latest->gatemac, "\x00\x00\x00\x00\x00\x00", 6)!=0 &&
	    (latest->gatemac[0]&0x1)==0){
	  memcpy(exist->gatemac, latest->gatemac, 6);
	}

	if(exist->linked_c != 0xff00){
		if(event_count(&exist->linked_c,5,
					   &exist->linked_t,5 )){
			exist->linked_c = 0xff00;
		}
	}

	if(0 && (exist->node_type & 0x40) == 0x40) {
		report_wips_event(exist, WIPS_EID_VIOLENT_CRACK_STA);
		exist->auth_c_crack = 0;
		exist->deauth_c_crack = 0;
	}

	if(exist->node_type & 0x02)
		report_wips_event(exist, WIPS_EID_WDS_STA);

	check_signal(latest,exist);
	check_address(latest, exist);
	sta_walk_wpolicy(exist, NULL);
	return 0;
}

static int wipsd_check_ieee80211_data(u8 *buf, int len,
					u8 fc02, u8 fc1, struct w_node *sta_val)
{
#define SEQ_CTL (22+heardaddr)
	int D_MAC=0;
	int S_MAC=0;
	int BSSIDMAC=0;
	struct w_node wnode;
	int t_type = 0;
	//char mac_str[20];
//	char *ip =NULL;
	int only_update_ap = 0;
//	struct protocol_node ptnode;
//	int ptnum;

	//WIPSD_DEBUG("%s-%d, wipsd_check_ieee80211_data!\t\n", __FUNCTION__, __LINE__);
	switch(fc02){
		case WLAN_FC02_STYPE_DATA:
			break;
		case WLAN_FC02_STYPE_DATA_CFACK:
			break;
		case WLAN_FC02_STYPE_DATA_CFPOLL:
			break;
		case WLAN_FC02_STYPE_DATA_CFACKPOLL:
			break;
		case WLAN_FC02_STYPE_NULLFUNC:
			sta_val->rates= 0;
			sta_val->is_null_data = 1;
			break;
		case WLAN_FC02_STYPE_CFACK:
			sta_val->rates= 0;
			break;
		case WLAN_FC02_STYPE_CFPOLL:
			sta_val->rates= 0;
			break;
		case WLAN_FC02_STYPE_CFACKPOLL:
			sta_val->rates= 0;
			break;
		case WLAN_FC02_STYPE_QOS_DATA:
			break;
		case WLAN_FC02_STYPE_QOS_DATA_CFACK:
			break;
		case WLAN_FC02_STYPE_QOS_DATA_CFPOLL:
			break;
		case WLAN_FC02_STYPE_QOS_DATA_CFACKPOLL:
			break;
		case WLAN_FC02_STYPE_QOS_NULLFUNC:
			sta_val->rates= 0;
			sta_val->is_null_data = 1;
			break;
		case WLAN_FC02_STYPE_QOS_CFACK:
			sta_val->rates= 0;
			break;
		case WLAN_FC02_STYPE_QOS_CFPOLL:
			sta_val->rates= 0;
			break;
		case WLAN_FC02_STYPE_QOS_CFACKPOLL:
			sta_val->rates= 0;
			break;
		default :
			return 0;
	}
	//WIPSD_DEBUG("%s-%d, wipsd_check_ieee80211_data!\t\n", __FUNCTION__, __LINE__);

	//sta_val.freq_band= (__u8) *((__u16 *)(&buf[CHANNEL-4]));
	switch(fc1){
		case WLAN_FC_TODS:
			D_MAC=(16+heardaddr);
			S_MAC=(10+heardaddr);
			BSSIDMAC=(4+heardaddr);
			memcpy( &sta_val->mac, &buf[S_MAC], 6);
			memcpy( &sta_val->bssid, &buf[BSSIDMAC], 6);
			memcpy( &sta_val->dstmac, &buf[D_MAC], 6);
#if 0
			//WIPSD_DEBUG("SMAC %02X-%02X-%02X-%02X-%02X-%02X, BSSID %02X-%02X-%02X-%02X-%02X-%02X, DMAC %02X-%02X-%02X-%02X-%02X-%02X!\t\n",
			//			NMACQUAD(sta_val->mac), NMACQUAD(sta_val->bssid), NMACQUAD(sta_val->dstmac));
			memset(&ptnode, 0, sizeof(ptnode));
		#if 0
			ptnum = wipsd_ieee80211_parse_data(buf + *(long*)(buf+4), len, &ptnode);
		#else
			ptnum = wipsd_ieee80211_parse_data(buf + heardaddr, len - heardaddr, &ptnode);
		#endif
			if( ptnum >= FIELD_OFFSET(struct protocol_node, app_src)){
			  //print_protocol_node(&ptnode, ptnum);
				memcpy(sta_val->addr_ipv4, ptnode.net_src, 4);
			}

			if( ptnode.net_type!=NET_TYPE_ARP && memcmp(sta_val->dstmac, sta_val->bssid, 6)!=0 &&
			    memcmp(sta_val->dstmac, "\x00\x00\x00\x00\x00\x00", 6)!=0 &&
			    (sta_val->dstmac[0]&0x1)==0 &&
			    memcmp(sta_val->mac, "\x00\x00\x00\x00\x00\x00", 6)!=0 &&
			    (sta_val->mac[0]&0x1)==0  ){
				memcpy(sta_val->gatemac, sta_val->dstmac, 6);
			}

			sta_val->net_type	=	ptnode.net_type;
			if( ptnum>=FIELD_OFFSET(struct protocol_node, app_src) &&
				ptnode.net_type==NET_TYPE_ARP
			   //&& memcmp(sta_val.dstmac, sta_val.bssid, 6)!=0
			   && memcmp(sta_val->dstmac, "\x00\x00\x00\x00\x00\x00", 6)!=0
			    && (sta_val->dstmac[0]&0x1)==0){
			   if(memcmp(ptnode.link_src, sta_val->dstmac, 6)==0){ //arp.src is wgate
			   	dobj_wgate_update(ptnode.link_src, ptnode.net_src);
			   }else if(memcmp(ptnode.link_dst, sta_val->dstmac, 6)==0){ //arp.dst is wgate
			   	dobj_wgate_update(ptnode.link_dst, ptnode.net_dst);
			   }
			}

			sprintf(mac_str, MACSTR, MAC2STR(sta_val->dstmac));
			if((ip = query_subnet_hash(mac_str)) != NULL){
				sta_val->internal_node = TRUE;
				strncpy(sta_val->ipv4, ip, sizeof(sta_val->ipv4));
				sta_val->ipv4[sizeof(sta_val->ipv4)-1] = '\0';
			}
#endif
			sta_val->node_type = 0x12;
            sta_val->is_assoc2ap = 1;
			sta_val->sequence_num = *((__u16 *)(&buf[SEQ_CTL]));
			swap16(sta_val->sequence_num);
			break;
		case WLAN_FC_FROMDS:
			D_MAC=(4+heardaddr);
			S_MAC=(16+heardaddr);
			BSSIDMAC=(10+heardaddr);
			memcpy( &sta_val->mac, &buf[D_MAC], 6);
			memcpy( &sta_val->bssid, &buf[BSSIDMAC], 6);
			memcpy( &sta_val->dstmac, &buf[S_MAC], 6);
			//WIPSD_DEBUG("SMAC %02X-%02X-%02X-%02X-%02X-%02X, BSSID %02X-%02X-%02X-%02X-%02X-%02X, DMAC %02X-%02X-%02X-%02X-%02X-%02X!\t\n",
			//		NMACQUAD(sta_val->mac), NMACQUAD(sta_val->bssid), NMACQUAD(sta_val->dstmac));

#if 0
			sprintf(mac_str, MACSTR, MAC2STR(sta_val->dstmac));
			memset(&ptnode, 0, sizeof(ptnode));
		#if 0
			ptnum = wipsd_ieee80211_parse_data(buf + *(long*)(buf+4), len, &ptnode);
		#else
			ptnum = wipsd_ieee80211_parse_data(buf + heardaddr, len - heardaddr, &ptnode);
		#endif
			if( ptnum >= FIELD_OFFSET(struct protocol_node, app_src)){
			  //print_protocol_node(&ptnode, ptnum);
				memcpy(sta_val->addr_ipv4, ptnode.net_dst, 4);
			}
			if( ptnode.net_type!=NET_TYPE_ARP && memcmp(sta_val->dstmac, sta_val->bssid, 6)!=0 &&
			    memcmp(sta_val->dstmac, "\x00\x00\x00\x00\x00\x00", 6)!=0 &&
			    (sta_val->dstmac[0]&0x1)==0 &&
			    memcmp(sta_val->mac, "\x00\x00\x00\x00\x00\x00", 6)!=0 &&
			    (sta_val->mac[0]&0x1)==0  ){
				memcpy(sta_val->gatemac, sta_val->dstmac, 6);
			}
			/*if( ptnum>=FIELD_OFFSET(struct protocol_node, app_src) && ptnode.net_type==NET_TYPE_ARP
			   &&  memcmp(ptnode.link_gate, "\x00\x00\x00\x00\x00\x00", 6)!=0 && (ptnode.link_gate[0] & 1==0)){
			   	dobj_wgate_update(ptnode.link_gate, ptnode.net_gate);
			}*/
			sta_val->net_type = ptnode.net_type;
			if( ptnum >= FIELD_OFFSET(struct protocol_node, app_src) && ptnode.net_type==NET_TYPE_ARP
			   //&& memcmp(sta_val.dstmac, sta_val.bssid, 6)!=0
			   && memcmp(sta_val->dstmac, "\x00\x00\x00\x00\x00\x00", 6)!=0
			    && (sta_val->dstmac[0]&0x1)==0){
			   if(memcmp(ptnode.link_src, sta_val->dstmac, 6)==0){ //arp.src is wgate
			   	dobj_wgate_update(ptnode.link_src, ptnode.net_src);
			   }else if(memcmp(ptnode.link_dst, sta_val->dstmac, 6)==0){ //arp.dst is wgate
			   	dobj_wgate_update(ptnode.link_dst, ptnode.net_dst);
			   }
			}

			if((ip = query_subnet_hash(mac_str)) != NULL){
				sta_val->internal_node = TRUE;
				strncpy(sta_val->ipv4, ip, sizeof(sta_val->ipv4));
				sta_val->ipv4[sizeof(sta_val->ipv4)-1] = '\0';
				if(buf[D_MAC] & 0x01){
					only_update_ap = 1;
					goto update_ap;
				}
			}
#endif
			if(buf[D_MAC] & 0x01) goto out;////???
			sta_val->node_type = 0x12;
            sta_val->is_assoc2ap = 1;
			break;
		case WLAN_FC_WDS:
			t_type = 1;
			D_MAC=(4+heardaddr);
			S_MAC=(10+heardaddr);
			BSSIDMAC=0;
			sta_val->node_type = 0x18;
			break;
		case WLAN_FC_ADHOC:
			t_type = 2;
			D_MAC=(4+heardaddr);
			S_MAC=(10+heardaddr);
			BSSIDMAC=(16+heardaddr);
			if(buf[D_MAC] & 0x01)
				goto out;

			memcpy( &sta_val->bssid, &buf[BSSIDMAC], 6);
			sta_val->node_type = 0x14;
			break;
		default :
			WIPSD_DEBUG("WLAN_FC1_NEW_STYPE!!! %02X\n",fc1);
			goto out;
	}

	if(sta_val->bssid[0] & 0x01){
		//WIPSD_DEBUG("%s-%d, debug!\t\n", __FUNCTION__, __LINE__);
		goto out;
	}
	if((buf[D_MAC] == 0x02) && ( memcmp( &buf[D_MAC], "\x02\x01\x00\x00\x00\x00", 6 ) == 0 )){
		//WIPSD_DEBUG("%s-%d, debug!\t\n", __FUNCTION__, __LINE__);
		goto out;
	}
	if(buf[D_MAC] & 0x01){
		if( memcmp( &buf[D_MAC], "\xff\xff\xff\xff\xff\xed", 6 ) == 0 ){
			set_wevent_bitmap(WIPS_EID_AIREPLAY_NG_FRAMG_STA, &sta_val->alert);
		}else if( buf[D_MAC] == 0xff && buf[D_MAC+5] != 0xff && buf[D_MAC+5] != 0xed){
			set_wevent_bitmap(WIPS_EID_AIREPLAY_NG_CHOP_STA, &sta_val->alert);
		}else if( !t_type && !(fc02 & 0x70) && (fcflags & 0x40) && !( buf[heardaddr + 27] & 0x20 )
			&& (memcmp( &buf[D_MAC], "\xff\xff\xff\xff\xff\xff", 6 ) == 0 )){
			/*sta_val->alert =*/ set_wevent_bitmap(WIPS_EID_AIREPLAY_NG_ARP_STA, &sta_val->alert);
		}else{
			/*sta_val->alert =*/ set_wevent_bitmap(WIPS_EID_BRAODCAST_STORM, &sta_val->alert);
		}
	}

	sta_val->refresh_time = fresh_time;
	sta_val->duration = *((__u16 *)(&buf[2+heardaddr]));
	swap16(sta_val->duration);
	sta_val->last_time= fresh_time;//time(&sta_val.last_time);
	sta_val->data_mum = len;
	if(fragframe && (len - fcs - heardaddr - 24) < 1024 ){
		switch(fc1){
			case WLAN_FC_TODS:
				set_wevent_bitmap(WIPS_EID_STA_SMALL_FRAG_PKG, &sta_val->alert);
				break;
			case WLAN_FC_FROMDS:
				set_wevent_bitmap(WIPS_EID_AP_SMALL_FRAG_PKG, &sta_val->alert);
				break;
		}
	}
	if(fcflags & 0x08){
		switch(fc1){
			case WLAN_FC_TODS:
				set_wevent_bitmap(WIPS_EID_STA_TOOMANY_RETRY, &sta_val->alert);
				break;
			case WLAN_FC_FROMDS:
				set_wevent_bitmap(WIPS_EID_AP_TOOMANY_RETRY, &sta_val->alert);
				break;
		}
	}
	if(buf[24+heardaddr] == 0xaa
		&&buf[25+heardaddr] == 0xaa
		&&buf[30+heardaddr] == 0x88
		&&buf[31+heardaddr] == 0x8e){
		sta_val->wpa8021x_mark = 1;
		if(buf[32+heardaddr] == 1){
			sta_val->wpa8021x_mark |= 2;
		}
	}

	if(t_type == 1){
		memcpy( &sta_val->mac, &buf[D_MAC], 6);
		memcpy( &sta_val->bssid, &buf[S_MAC], 6);
#ifdef X86_FINDIP
		sprintf(mac_str, NMACQUAD_FMT, NMACQUAD(sta_val->mac));

		find_lan_ip(mac_str, &ip);
		if(ip != NULL) {
			strcpy( sta_val->ipv4, (char *)ip);
			sta_val->internal_node = 1;
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
		}
#endif

		if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2APLIST, check_wdsdata_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}

		memcpy( &sta_val->mac, &buf[S_MAC], 6);
		memcpy( &sta_val->bssid, &buf[D_MAC], 6);

#ifdef X86_FINDIP
		sprintf(mac_str, NMACQUAD_FMT, NMACQUAD(sta_val->mac));
		memset(sta_val->ipv4,0,24);

		find_lan_ip(mac_str, &ip);
		if(ip != NULL) {
			strcpy( sta_val->ipv4, (char *)ip);
			sta_val->internal_node = 1;

		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
		}
#endif
		if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2APLIST, check_wdsdata_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}
	} else if(t_type == 2){
		memcpy( &sta_val->mac, &buf[D_MAC], 6);
#ifdef X86_FINDIP
		sprintf(mac_str, NMACQUAD_FMT, NMACQUAD(sta_val->mac));

		find_lan_ip(mac_str, &ip);
		if(ip != NULL) {
			strcpy( sta_val->ipv4, (char *)ip);
			sta_val->internal_node = 1;

		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
		}
#endif

		if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2STALIST, check_data_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}

		memcpy( &sta_val->mac, &buf[S_MAC], 6);
#ifdef X86_FINDIP
		sprintf(mac_str, NMACQUAD_FMT, NMACQUAD(sta_val->mac));
		memset(sta_val->ipv4,0,16);

		find_lan_ip(mac_str, &ip);
		if(ip != NULL) {
			strcpy( sta_val->ipv4, (char *)ip);
			sta_val->internal_node = 1;

		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
		}
#endif
		if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2STALIST, check_data_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}
	}else{
#ifdef X86_FINDIP
		sprintf(mac_str, NMACQUAD_FMT, NMACQUAD(sta_val->mac));

		find_lan_ip(mac_str, &ip);
		if(ip != NULL) {
			strcpy( sta_val->ipv4, (char *)ip);
			sta_val->internal_node = 1;

		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
		}
#endif


#if 0
//update_ap:
		if(1 /*sta_val.internal_node == TRUE
			|| test_wevent_bitmap(WIPS_EID_AP_SMALL_FRAG_PKG, &sta_val.alert)
			|| test_wevent_bitmap(WIPS_EID_AP_TOOMANY_RETRY, &sta_val.alert)*/) {
			memcpy( &wnode, sta_val, sizeof(struct w_node));
			memcpy( &wnode.mac, &wnode.bssid, 6);

			//bssid is 0x01 broadcast
			if (wnode.bssid[0] & 0x01){
				WIPSD_DEBUG("func:%s ,line:%d  find unauth_ap!\t\n",__func__,__LINE__);
				report_wips_event(&wnode, WIPS_EID_UNAUTH_AP);
			}else{
				wnode.node_type = 1;
				wnode.signal = -95;
				if(find_wlistnode_sniffer(&wnode, LIST_TASK_ADD2APLIST, check_data_hook)!=0){
					printf("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
				}
			}
		}
#endif
		//add by dingkang for syslog to server
		send_ap_info(sta_val,"wipsd_check_ieee80211_data");

		if(only_update_ap) {
			WIPSD_DEBUG("%s-%d, debug!\t\n", __FUNCTION__, __LINE__);
			goto out;
		}

		if(test_wevent_bitmap(WIPS_EID_WIRELESS_MOOCH, &wnode.alert)){
			set_wevent_bitmap(WIPS_EID_WIRELESS_MOOCH, &sta_val->alert);
		}
		if(find_wlistnode_sniffer(sta_val, LIST_TASK_ADD2STALIST, check_data_hook)!=0){
			WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
		}

	}

	return 0;
out:

	return 0;
#undef SEQ_CTL
}

int check_deauth_hook(struct w_node * latest,struct w_node * exist)
{
//	memcpy( exist->ipv4,latest->ipv4,16);
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	exist->reason_code	  = latest->reason_code ;
//	exist->last_time		= latest->last_time ;
	exist->deauth_c_crack   += 1;
	exist->freq_band		 = latest->freq_band ;

	if(event_count(&exist->deauth_c,deauth_cmax,
				   &exist->deauth_t,deauth_tmax )){
		struct w_node *node;
		if(0 == get_wlist_node((char *)latest->dstmac, &node)){
			if((exist->reason_code == 7) && (node->reason_code == 7)){
				report_wips_event(exist, WIPS_EID_AIREPLAY_NG_DEAUTH_STA);
			}else if((exist->reason_code == 1) && (node->reason_code == 1)){
				report_wips_event(exist, WIPS_EID_MDK3_DEAUTH_STA);
			}else{
				report_wips_event(exist, WIPS_EID_DEAUTH_STA);
			}
		}else{
			report_wips_event(exist, WIPS_EID_DEAUTH_STA);
		}
	}

	if(0 && exist->reason_code == 7) {
		report_wips_event(exist, WIPS_EID_VIOLENT_CRACK_STA);
		exist->auth_c_crack = 0;
		exist->deauth_c_crack = 0;
#if 0
		if(exist->deauth_c > 0)
			;//exist->deauth_c--;
#endif
	}

	if(exist->node_type & 0x06) {
		report_wips_event(exist, WIPS_EID_STA_OFF_NETWORK);
		clear_wips_event(exist, WIPS_EID_STA_ON_NETWORK);
	}

	if(0 && (exist->node_type & 0x40) == 0x40) {
		report_wips_event(exist, WIPS_EID_VIOLENT_CRACK_STA);
		exist->auth_c_crack = 0;
		exist->deauth_c_crack = 0;
	}
	check_lsatpkgtype(latest, exist, WIPS_PKGTYPE_DEAUTH);
	check_address(latest, exist);
	exist->linked_c = 0;

    //check_relay_unauth_ap(exist);

	return 0;
}

int check_disassoc_hook(struct w_node * latest,struct w_node * exist)
{
//	memcpy( exist->ipv4,latest->ipv4,16);
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
	exist->reason_code	  = latest->reason_code ;
//	exist->last_time		= latest->last_time ;
	exist->freq_band		 = latest->freq_band ;

	if(exist->node_type & 0x06) {
		report_wips_event(exist, WIPS_EID_STA_OFF_NETWORK);
		clear_wips_event(exist, WIPS_EID_STA_ON_NETWORK);
	}
	if(event_count(&exist->deassoc_c,deassoc_cmax,
				   &exist->deassoc_t,deassoc_tmax )){
		struct w_node *node;
		if(0 == get_wlist_node((char *)latest->dstmac, &node)){
			if((exist->reason_code == 1) && (node->reason_code == 1)){
				report_wips_event(exist, WIPS_EID_MDK3_DEASSO_STA);
			}else{
				report_wips_event(exist, WIPS_EID_DEASSO_STA);
			}
		}else{
			report_wips_event(exist, WIPS_EID_DEASSO_STA);
		}
	}
	check_lsatpkgtype(latest, exist, WIPS_PKGTYPE_DEAUTH);
	check_address(latest, exist);
	exist->linked_c = 0;
    //check_relay_unauth_ap(exist);
    
	return 0;
}

static int check_disassoc_deauth(unsigned char *buf, int len, int type, unsigned char fc1, struct w_node *wnode_dd)
{
#define D_MAC (4+heardaddr)
#define S_MAC (10+heardaddr)
#define BSSIDMAC (16+heardaddr)
#define REASON_CODE (24+heardaddr)
	if(len != 26+heardaddr+fcs)
		return 1;

	if(buf[2+heardaddr]==0x75 && buf[3+heardaddr]==0 )
		return 2;

	if(buf[22+heardaddr]==0x40 && buf[23+heardaddr]==0x0a )
		return 2;


	memcpy( wnode_dd->mac,&buf[S_MAC],6);
	memcpy( wnode_dd->dstmac,&buf[D_MAC],6);
	memcpy( wnode_dd->bssid,&buf[BSSIDMAC],6);
	wnode_dd->reason_code = *((__u16 *)(&buf[REASON_CODE]));
	swap16(wnode_dd->reason_code);
    wnode_dd->is_assoc2ap = 0;

	wnode_dd->refresh_time = fresh_time;
#if 0
	wnode_dd.channel = *((__u32 *)(&buf[CHANNEL]));

	if(fcs ==4){
		wnode_dd.rates= (__u16) buf[RATE];
	}else{
		wnode_dd.rates= *((__u32 *)(&buf[RATE]));
	}
#endif
	if(type == 0){
		__u32 rate_tmp = 0;
		deauthenticate_type *deauth;
		deauth = (deauthenticate_type *)(&buf[heardaddr]);
		rate_tmp = deauth->sc[1] * 0x100 + deauth->sc[0];
		if( rate_tmp == wnode_dd->rates)
			return 2;
	}
#if 0
	if(NOISE){
		wnode_dd.noise  = *((int *)(&buf[NOISE]));//-96;//
		wnode_dd.signal = *((int *)(&buf[SINGLE]));
	}else{
		wnode_dd.noise  = -96;//
		wnode_dd.signal = *((int *)(&buf[SINGLE])) - 96;
	}
#endif
	wnode_dd->last_time= fresh_time;//time(&wnode_dd.last_time);
	//wnode_dd.freq_band= (__u8) *((__u16 *)(&buf[CHANNEL-4]));

#ifdef X86_FINDIP
	char mac_str[20];
	char *ip;

    sprintf(mac_str, NMACQUAD_FMT,NMACQUAD(wnode_dd->mac));

	find_lan_ip(mac_str, &ip);
	if(ip != NULL) {
		strcpy( wnode_dd->ipv4, (char *)ip);
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
	}
#endif

	switch(fc1){
		case WLAN_FC_TODS:{
			wnode_dd->node_type = 0x12;
			if(type){
				if(find_wlistnode_sniffer(wnode_dd, LIST_TASK_ADD2STALIST,
					check_disassoc_hook)!=0){
					WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
				}
			}else{
				if(find_wlistnode_sniffer(wnode_dd, LIST_TASK_ADD2STALIST,
					check_deauth_hook)!=0){
					WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
				}
			}
		}
			break;
		case WLAN_FC_FROMDS:{
			wnode_dd->node_type = 0x01;
			if(type){
				if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE/*LIST_TASK_ADD2APLIST*/,
					check_disassoc_hook)!=0){
					WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
				}
			}else{
				if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE/*LIST_TASK_ADD2APLIST*/,
					check_deauth_hook)!=0){
					WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
				}
				memcpy( wnode_dd->mac,&buf[D_MAC],6);
				wnode_dd->node_type = 0x12;
				if(find_wlistnode_sniffer(wnode_dd, LIST_TASK_ADD2STALIST,
					check_deauth_hook)!=0){
					WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
				}
			}
		}
			break;
		case 0 :
			if(memcmp( wnode_dd->mac,wnode_dd->bssid,6) != 0){//sta
				wnode_dd->node_type = 0x12;
				if(type){
					if(find_wlistnode_sniffer(wnode_dd, LIST_TASK_ADD2STALIST,
						check_disassoc_hook)!=0){
						WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
					}
				}else{
					if(find_wlistnode_sniffer(wnode_dd, LIST_TASK_ADD2STALIST,
						check_deauth_hook)!=0){
						WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
					}
				}
			}else{//ap
				wnode_dd->node_type = 0x01;
				if(type){
					if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE/*LIST_TASK_ADD2APLIST*/,
						check_disassoc_hook)!=0){
						WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
					}
				}else{
					if(find_wlistnode_sniffer(wnode_dd, NO_ADD_NODE/*LIST_TASK_ADD2APLIST*/,
						check_deauth_hook)!=0){
						WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
					}
					memcpy( wnode_dd->mac,&buf[D_MAC],6);
					wnode_dd->node_type = 0x12;
					if(find_wlistnode_sniffer(wnode_dd, LIST_TASK_ADD2STALIST,
						check_deauth_hook)!=0){
						WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
					}
				}
			}
			break;
		default :
			//WIPSD_DEBUG("WLAN_FC1_NEW_STYPE!!! %02X\n",fc1);
			return 0;
	}

#undef D_MAC
#undef S_MAC
#undef BSSIDMAC
#undef REASON_CODE
	return 0;
}

int check_auth_hook(struct w_node * latest,struct w_node * exist)
{
//	memcpy( exist->ipv4,latest->ipv4,16);
	if((wireless_node_age !=0) &&(exist->last_time+wireless_node_age <  latest->refresh_time))
	{
		exist->up_time		= latest->refresh_time ;
	}

	exist->last_time = exist->refresh_time	 = latest->refresh_time ;
//	exist->last_time		= latest->last_time ;
	exist->auth_c_crack   += 1;

	if(event_count(&exist->auth_c,auth_cmax,
				   &exist->auth_t,auth_tmax )){
		report_wips_event(exist, WIPS_EID_AUTH_FLOOD_STA);
	}

	exist->linked_c = 0;
	if(0 && (exist->node_type & 0x40) == 0x40) {
		report_wips_event(exist, WIPS_EID_VIOLENT_CRACK_STA);
		exist->auth_c_crack = 0;
		exist->deauth_c_crack = 0;
	}
	check_lsatpkgtype(latest, exist, WIPS_PKGTYPE_DEFAULT);
	check_address(latest, exist);

    //check_relay_unauth_ap(exist);

	exist->auth_mark = 1;
	exist->auth_time = fresh_time;
	return 0;
}

static int check_auth(unsigned char *buf, int len, struct w_node *sta_val)
{
#define D_MAC (4+heardaddr)
#define S_MAC (10+heardaddr)
#define BSSIDMAC (16+heardaddr)
	if(len < 30+heardaddr+fcs)
		return 0;

	memcpy( sta_val->mac,&buf[D_MAC],6);
	memcpy( sta_val->bssid,&buf[BSSIDMAC],6);
	sta_val->refresh_time = fresh_time;
#if 0
	sta_val.channel = *((__u32 *)(&buf[CHANNEL]));

	 if(fcs ==4){
		sta_val.rates= (__u16) buf[RATE];
	}else{
		sta_val.rates= *((__u32 *)(&buf[RATE]));
	}

	if(NOISE){
		sta_val.noise  = *((int *)(&buf[NOISE]));//-96;//
		sta_val.signal = *((int *)(&buf[SINGLE]));
	}else{
		sta_val.noise  = -96;//
		sta_val.signal = *((int *)(&buf[SINGLE])) - 96;
	}
#endif
	sta_val->last_time= fresh_time;//time(&sta_val.last_time);
	//sta_val.freq_band= (__u8) *((__u16 *)(&buf[CHANNEL-4]));

#ifdef X86_FINDIP
	char mac_str[20];
	char *ip;

    sprintf(mac_str, NMACQUAD_FMT, NMACQUAD(sta_val->mac));

	find_lan_ip(mac_str, &ip);
	if(ip != NULL) {
		strcpy( sta_val->ipv4, (char *)ip);
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
	}
#endif

	if(find_wlistnode_sniffer(sta_val, NO_ADD_NODE/*LIST_TASK_ADD2APLIST*/, check_auth_hook)!=0){
		WIPSD_DEBUG("check wnode err in %s of %d line\n", __FUNCTION__, __LINE__);
	}

#undef D_MAC
#undef S_MAC
#undef BSSIDMAC

	return 0;
}


int wipsd_handle_wlansniffrm(u8 *buf, int len, struct wipsd_interface *wipsd_itf, struct sockaddr_in *addr)
{
	unsigned char fc01;
	unsigned char fc1;
	unsigned char fc02;
	u32 flags = 0;
	u32 hdr_len = 0;
	struct w_node sta_val;
	int ret = 0;

	if(!buf || !wipsd_itf || !addr){
		//vsos_assert(0);
		return 1;
	}

    memset((void *)&sta_val, 0, sizeof(sta_val));
    memcpy(sta_val.prober_mac,buf+(len-6),6);
    len-=6;

	fcs = 0;// ap send frame doesn't have fcs
	if(wipsd_ieee80211_packet_prism(buf, &hdr_len)) {
		//WIPSD_DEBUG("Prism header, %d bytes read, wireless header %d\n", len, hdr_len);
		heardaddr = hdr_len;
		if(hdr_len > len){
			WIPSD_DEBUG("Invalid prism header packet!\t\n");
			return 1;
		}

		ret = wipsd_ieee80211_prism_parse(buf, &sta_val);
		if(!ret){
			WIPSD_DEBUG("Parse radiotap failed!\t\n");
			return 1;
		}
	}
	else if(wipsd_ieee80211_packet_radiotap(buf, &hdr_len)){
		heardaddr = hdr_len;
		//WIPSD_DEBUG("Radiotap header, %d bytes read, wireless header %d\n", len, hdr_len);
		if(hdr_len > len){
			WIPSD_DEBUG("Invalid radiotap header packet!\t\n");
			return 1;
		}
		ret = wipsd_ieee80211_radiotap_parse(buf, len, &sta_val);
		if(ret){
			WIPSD_DEBUG("Parse radiotap failed!\t\n");
			return 1;
		}

		if(signal_threshold  && (sta_val.signal < signal_threshold))
			return 1;

	}
	else {
		WIPSD_DEBUG("Invalid 802.11 packet!\t\n");
		return 1;
	}

	recv_packet++;
	if(flags & 1){
		check_freq_err(&sta_val);
		return 1;
	}

	sta_val.wipsd_itf = wipsd_itf;
	memcpy((void *)&sta_val.addr, addr, sizeof(struct sockaddr_in));
	fc01 = buf[heardaddr] & IEEE80211_TYPE_MASK;// frm->frame_control[0] & 0x0c;
	fc02 = buf[heardaddr] & IEEE80211_SUBTYPE_MASK;// frm->frame_control[0] & 0xf0;
	fc1 = buf[heardaddr+1] & IEEE80211_DS_MASK;// frm->frame_control[1] & 0x03;
	fcflags = buf[heardaddr+1];
	if(buf[heardaddr+1] & IEEE80211_RETRANSMISSION_MASK){
		check_freq_interference(&sta_val);
		check_freq_suppression(&sta_val);
	}

	if(buf[heardaddr+1] & IEEE80211_FRAGMENT_MASK){
		fragframe = 1;
	}else{
		fragframe = 0;
	}
#if 0
#ifdef DEBUG_WIPSD
	WIPSD_DEBUG("len %d, type %02X, subtype %02X, ds %02X, channel:%d, band:%d!\t\n",
		len, fc01, fc02, fc1, sta_val.channel, sta_val.freq_band);
#endif
#endif

	switch (fc01)
	{
		case WLAN_FC_TYPE_DATA:
			//WIPSD_DEBUG("WLAN_FC_TYPE_DATA:\n");
			//show_hdr_data(frm);
			wipsd_check_ieee80211_data(buf, len, fc02, fc1, &sta_val);
			break;
		case WLAN_FC_TYPE_MGMT:
			//WIPSD_DEBUG("WLAN_FC_TYPE_MGMT:\n");
			//show_hdr_management(frm);
			switch(fc02){
				case WLAN_FC02_STYPE_ASSOC_REQ:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_ASSOC_REQ:\n");
					wipsd_check_ieee80211_assoc_reassoc_req(buf,len,1, &sta_val);
					break;
				case WLAN_FC02_STYPE_ASSOC_RESP:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_ASSOC_RESP:\n");
					check_assoc_reassoc_resp(buf,len,1);
					break;
				case WLAN_FC02_STYPE_REASSOC_REQ:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_REASSOC_REQ:\n");
					wipsd_check_ieee80211_assoc_reassoc_req(buf,len, 0, &sta_val);
					break;
				case WLAN_FC02_STYPE_REASSOC_RESP:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_REASSOC_RESP:\n");
					check_assoc_reassoc_resp(buf,len, 0);
					break;
				case WLAN_FC02_STYPE_PROBE_REQ:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_PROBE_REQ:\n");
					check_probe_req(buf, len, &sta_val);
					break;
				case WLAN_FC02_STYPE_PROBE_RESP:
					check_probe_resp(buf, len, &sta_val);
					break;
				case WLAN_FC02_STYPE_BEACON:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_BEACON:\n");
					check_beacon(buf,len, &sta_val);
					break;
				case WLAN_FC02_STYPE_ATIM:
					break;
				case WLAN_FC02_STYPE_DISASSOC:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_DISASSOC:\n");
					check_disassoc_deauth(buf,len, 1, fc1, &sta_val);
					break;
				case WLAN_FC02_STYPE_AUTH:
					check_auth(buf, len, &sta_val);
					break;
				case WLAN_FC02_STYPE_DEAUTH:
					//WIPSD_DEBUG("WLAN_FC02_STYPE_DEAUTH:\n");
					check_disassoc_deauth(buf,len,0, fc1, &sta_val);
					break;
				default :
					break;
			}
			break;
		case WLAN_FC_TYPE_CTRL:
			//WIPSD_DEBUG("WLAN_FC_TYPE_CTRL:\n");
			//switch (WLAN_FC_GET_STYPE(fc))
			switch (fc02){
				case WLAN_FC_STYPE_PSPOLL:
					//show_hdr_pspoll(frm);
					//WIPSD_DEBUG("WLAN_FC_STYPE_PSPOLL:\n");
					break;
				case WLAN_FC_STYPE_RTS:
					//show_hdr_rts(frm);
					//WIPSD_DEBUG("WLAN_FC_STYPE_RTS:\n");
					check_rts(buf, len, &sta_val);
					break;
				case WLAN_FC_STYPE_CFEND:
				case WLAN_FC_STYPE_CFENDACK:
					//WIPSD_DEBUG("WLAN_FC_STYPE_CFEND WLAN_FC_STYPE_CFENDACK:\n");
					//show_hdr_cfend(frm);
					break;
				case WLAN_FC_STYPE_CTS:
					//WIPSD_DEBUG("WLAN_FC_STYPE_CTS:\n");
					check_cts(buf, len, &sta_val);
					break;
				case WLAN_FC_STYPE_ACK:
					//WIPSD_DEBUG("WLAN_FC_STYPE_ACK:\n");
					//show_hdr_cts(frm);
					check_ack(buf, len, &sta_val);
					break;
				default :
					break;
			}
			break;
		default :
			break;
	}

	loop_counts++;
	return 0;
}


void init_wevent(void)
{
#define GRP_HEAD	"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"name\",\"cmd_name\") values "
#define UNGRP_HEAD	"INSERT INTO wevent(\"id\", \"is_grp\", \"grp_id\", \"pri\", \"name\",\"cmd_name\",\"desc\") values "
	char cmd[WIPS_EID_MAX][2048];
	char create[1024];
	int ret, i;
	sqlite3 *sql = NULL;

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("sqlite open err !!!");
		exit(1);
	}

	sqlite3_exec(sql,"drop table wevent",NULL,NULL,NULL);
	memset(create, 0 ,sizeof(create));
	sprintf(create,
		"CREATE TABLE wevent(id nvarchar(4), is_grp nvarchar(4), grp_id nvarchar(4), "
		"pri nvarchar(8), name nvarchar(32), cmd_name nvarchar(32),desc nvarchar(512),ref nvarchar(%d));",
		WEVENT_NAME_LEN);
	sqlite3_exec(sql, create, NULL,NULL,NULL);


//起始ID不能变，ID必须顺序增加
	sprintf(cmd[WIPS_EID_ALL], GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"全部\",\"%s\");", WIPS_EID_ALL, 1, 0, wips_event_table[WIPS_EID_ALL].name);

	sprintf(cmd[WIPS_EID_ERR_CFG_GRP], GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线安全策略类\",\"%s\");",
		WIPS_EID_ERR_CFG_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_ERR_CFG_GRP].name);
	sprintf(cmd[WIPS_EID_NO_CRYPT_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线安全策略-未设置加密方式\",\"%s\",\"AP未设置任何加密，作为开放系统工作，此时任何无线终端均可接入AP，且数据传输为明文，存在较大的安全风险。\");",
		WIPS_EID_NO_CRYPT_AP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_NO_CRYPT_AP].name);
	sprintf(cmd[WIPS_EID_CRYPT_WEP_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线安全策略-加密方式为WEP\",\"%s\", \"WEP，有线等效加密，采用RC4串流加密技术，存在密钥长度不足、IV雷同和变造的报文等弱点，黑客通过捕获一定数量的报文，或主动激发出所需的报文，来破解WEP，多款黑客工具已经可以轻易做到这一点。\");",
		WIPS_EID_CRYPT_WEP_AP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_CRYPT_WEP_AP].name);
	sprintf(cmd[WIPS_EID_WPS_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线安全策略-发现开启了WPS功能的无线设备\", \"%s\",\"WPS（WiFi Protected Setup，WiFi保护设置），它是由WiFi联盟组织实施的可选认证项目，使用8位PIN码作为身份认证，目前的技术已经可以暴力破解该PIN码，存在信息泄露的安全隐患；目前有部分无线产品PIN码设置与MAC相关，可以直接根据MAC计算出PIN码，风险极大。\");",
		WIPS_EID_WPS_AP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_WPS_AP].name);
	sprintf(cmd[WIPS_EID_WDS_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-AP开启WDS功能\",\"%s\", \"当发现AP开启了WDS中继模式，上报一次该报警；开启了WDS中继模式的AP，可以扩展WLAN网络的覆盖范围，但也会显著降低无线网络的性能，吞吐率很可能降低为原来的一半；另外，由于中继模式扩大了无线信号的覆盖范围，且可能简化了用户认证过程，因此可能带来较大的安全隐患。\");",
		WIPS_EID_WDS_AP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_WDS_AP].name);
	sprintf(cmd[WIPS_EID_WDS_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-无线终端开启了WDS功能\", \"%s\",\"WDS可以把有线网络的数据，通过无线网络当中继架构来传输，藉此可将数据传送到另外一个无线网络环境，或者是另外一个有线网络。因为通过无线网络形成虚拟的线路，所以通常被称为无线桥接功能。开启WDS功能的STA可能会被黑客用于多跳攻击的节点。\");",
		WIPS_EID_WDS_STA, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_WDS_STA].name);
	sprintf(cmd[WIPS_EID_AD_HOC],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-发现开启了AdHoc的无线设备\",\"%s\", \"工作在Ad-Hoc模式的无线设备，Ad-Hoc允许两台无线设备直接相连，增加了信息泄漏的风险，给内网安全带来隐患。\");",
		WIPS_EID_AD_HOC, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_AD_HOC].name);
	sprintf(cmd[WIPS_EID_AD_PKG],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-无线网络中检测到AdHoc设备或通信\",\"%s\", \"两台开启了Ad Hoc的无线设备可以不通过AP，直接进行通信；如果通信的信道与附近的AP相同或接近，将极大的影响AP的性能；另外，由于点对点的无线通信不遵循无线网络安全策略，存在比较大的数据泄漏风险。\");",
		WIPS_EID_AD_PKG, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_AD_PKG].name);
	sprintf(cmd[WIPS_EID_UNAUTH_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-发现流氓AP\",\"%s\", \"检测到未授权的流氓AP，内网中存在较大的信息泄漏风险。\");",
		WIPS_EID_UNAUTH_AP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_UNAUTH_AP].name);
//	sprintf(cmd[WIPS_EID_INVALID_FREQ_AP],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-AP使用未授权信道\", \"工作在非802.11合法信道的AP，非法信道通常位于合法信道之间或之外，由于可逃避多数无线安全设备的检测，该威胁较为隐蔽。\");",
//		WIPS_EID_INVALID_FREQ_AP, 0, WIPS_EID_ERR_CFG_GRP);
	sprintf(cmd[WIPS_EID_STA_PROXY_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-发现代理AP\",\"%s\", \"接入无线网络的合法客户端设备同时具有架设无线接入点的功能，该设备私自开启AP功能，通过无线桥接的方式将内部无线网络资源连接到外网，信息泄露风险较大。\");",
		WIPS_EID_STA_PROXY_AP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_STA_PROXY_AP].name);
	sprintf(cmd[WIPS_EID_CLOSE_PSPE],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线安全策略-无线网络的PSPF功能未启用\", \"%s\",\"PSPF（ Public Secure Packet Forwarding，公共安全包转发）未启用，意味着关联到同一AP的两台无线终端可以相互通信，这对性能和安全两方面都带来隐患。\");",
		WIPS_EID_CLOSE_PSPE, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_CLOSE_PSPE].name);
//	sprintf(cmd[WIPS_EID_UNAUTH_MAC_FACT],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-未授权的无线设备厂商\", \"接入网络的AP或无线终端，使用了无线安全策略不允许的厂商设备。\");",
//		WIPS_EID_UNAUTH_MAC_FACT, 0, WIPS_EID_ERR_CFG_GRP);
	sprintf(cmd[WIPS_EID_WPA_REFUSED],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线安全策略-无线安全类型错误\", \"%s\",\"在无线报文中，出现802.11i或WPA2安全错误。\");",
		WIPS_EID_WPA_REFUSED, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_WPA_REFUSED].name);
	sprintf(cmd[WIPS_EID_FORBID_CHANNEL],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-非法的信道\", \"%s\",\"信道不符合中国无线频段的规定，采用了其他国家的信道，通常为了逃避检查，或为了躲避干扰。\");",
		WIPS_EID_FORBID_CHANNEL, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_FORBID_CHANNEL].name);
	sprintf(cmd[WIPS_EID_UNAUTH_ESSID],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-非法的ESSID\", \"%s\",\"附近的无线网络中，出现了可能存在假冒/欺骗风险的ESSID，存在信息泄漏风险。\");",
		WIPS_EID_UNAUTH_ESSID, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_UNAUTH_ESSID].name);
	sprintf(cmd[WIPS_EID_AP_BRAODCAST_SSID],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线安全策略-AP使用了广播的ESSID\", \"%s\",\"AP在广播发送的Beacon帧中，包含ESSID（扩展服务集标识），允许所有的无线终端得到该ESSID，其中也包括使用无线嗅探工具得到该ESSID。\");",
		WIPS_EID_AP_BRAODCAST_SSID, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_AP_BRAODCAST_SSID].name);
	sprintf(cmd[WIPS_EID_AP_DEFAULTSSID],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线安全策略-AP的ESSID为缺省值\", \"%s\",\"AP广播的Beacon帧中包含缺省的ESSID值，WIPS中包含缺省SSID的列表。\");",
		WIPS_EID_AP_DEFAULTSSID, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_AP_DEFAULTSSID].name);
	sprintf(cmd[WIPS_EID_UNAUTH_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线安全策略-发现未授权终端\",\"%s\", \"未授权的无线终端。\");",
		WIPS_EID_UNAUTH_STA, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_UNAUTH_STA].name);
	sprintf(cmd[WIPS_EID_AUTHSTA_UNAUTHAP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-授权终端关联未授权AP\",\"%s\", \"无线终端与未知或未授权的AP关联，每关联一次，触发一次告警。\");",
		WIPS_EID_AUTHSTA_UNAUTHAP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_AUTHSTA_UNAUTHAP].name);
//	sprintf(cmd[WIPS_EID_UNAUTH_DHCP],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线安全策略-无线终端开启了DHCP_Server\", \"无线终端开启了DHCP服务，有可能为非法的DHCP服务器，并存在安全风险。\");",
//		WIPS_EID_UNAUTH_DHCP, 0, WIPS_EID_ERR_CFG_GRP);
	sprintf(cmd[WIPS_EID_AUTHSTA_EXTAP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-授权终端关联外部AP\",\"%s\", \"无线终端与外部AP关联，每关联一次，触发一次告警。\");",
		WIPS_EID_AUTHSTA_EXTAP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_AUTHSTA_EXTAP].name);
	sprintf(cmd[WIPS_EID_UNAUTHSTA_INTERAP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线安全策略-未授权终端关联内部AP\",\"%s\", \"未授权的无线终端与内部AP关联，每关联一次，触发一次告警。\");",
		WIPS_EID_UNAUTHSTA_INTERAP, 0, WIPS_EID_ERR_CFG_GRP,wips_event_table[WIPS_EID_UNAUTHSTA_INTERAP].name);
//	sprintf(cmd[WIPS_EID_AP_FORBIDRATE],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线安全策略-AP使用未授权速率\", \"未授权。\");",
//		WIPS_EID_AP_FORBIDRATE, 0, WIPS_EID_ERR_CFG_GRP);
//	sprintf(cmd[WIPS_EID_STA_FORBIDRATE],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线安全策略-无线终端使用未授权速率\", \"未授权。\");",
//		WIPS_EID_STA_FORBIDRATE, 0, WIPS_EID_ERR_CFG_GRP);


	sprintf(cmd[WIPS_EID_PROBE_GRP], GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线扫描探测类\",\"%s\");", WIPS_EID_PROBE_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_PROBE_GRP].name);
//	sprintf(cmd[WIPS_EID_NULLPROBE_RESP],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线扫描-空探测响应\", \"NullProbeResponse，非法无线报文，可能存在攻击行为，并影响无线网络性能。\");",
//		WIPS_EID_NULLPROBE_RESP, 0, WIPS_EID_PROBE_GRP);
	sprintf(cmd[WIPS_EID_UNAUTHSTA_PROBE_TOOMANY],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线扫描--发现未授权终端扫描无线网络\", \"%s\",\"未授权的无线终端发送了一定数量的探测请求，用户获取无线网络信息；如果情况持续，可能会导致无线网络的带宽降低、延时增加等低效问题。\");",
		WIPS_EID_UNAUTHSTA_PROBE_TOOMANY, 0, WIPS_EID_PROBE_GRP,wips_event_table[WIPS_EID_UNAUTHSTA_PROBE_TOOMANY].name);


	sprintf(cmd[WIPS_EID_SPOOFING_GRP],	GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线欺骗类\",\"%s\");", WIPS_EID_SPOOFING_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_SPOOFING_GRP].name);
	sprintf(cmd[WIPS_EID_FISHING_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-钓鱼AP\", \"%s\",\"通过伪造信息来搭设钓鱼AP，用于仿冒内网合法AP，欺骗无线用户与其关联，攻击者通常会试图获取无线客户的网络加密信息，如果钓鱼成功，更可继续获得更多有价值的信息。\");",
		WIPS_EID_FISHING_AP, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_FISHING_AP].name);
	sprintf(cmd[WIPS_EID_HOTSPOTTER_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-HotSpotter\", \"%s\",\"通过监听客户端的探测帧，利用自身的常用热点SSID构造假冒AP，允许客户端认证和关联，建立连接后发起下一步攻击。\");",
		WIPS_EID_HOTSPOTTER_AP, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_HOTSPOTTER_AP].name);
	sprintf(cmd[WIPS_EID_AIRBASE_NG_FAKE_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-Airbase-ng_Fake_AP\", \"%s\",\"攻击者使用Airbase-ng将其计算机伪装成客户端希望接入的AP，吸引客户端关联到非法设备，以获取更重要的数据信息\");",
		WIPS_EID_AIRBASE_NG_FAKE_AP, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_AIRBASE_NG_FAKE_AP].name);
	sprintf(cmd[WIPS_EID_MDK3_BEACON_FLOOD_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-MDK3_Fake_AP\", \"%s\",\"MDK3是无线DOS攻击工具，MDK3 Fake AP伪造大量BEACON帧使终端设备误认为周边有大量AP存在，干扰无线网络的正常使用。\");",
		WIPS_EID_MDK3_BEACON_FLOOD_AP, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_MDK3_BEACON_FLOOD_AP].name);
	sprintf(cmd[WIPS_EID_MITM_ATTACK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-中间人攻击\", \"%s\",\"攻击者进入无线网路，冒充网关，把所有内网流量进行解析，获取一些有价值的数据信息。\");",
		WIPS_EID_MITM_ATTACK, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_MITM_ATTACK].name);
	sprintf(cmd[WIPS_EID_ARP_SPOOFING_ATTACK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-ARP欺骗\",\"%s\", \"攻击者进入无线网路，冒充网关，把所有内网流量进行解析，获取一些有价值的数据信息。\");",
		WIPS_EID_ARP_SPOOFING_ATTACK, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_ARP_SPOOFING_ATTACK].name);
	sprintf(cmd[WIPS_EID_SEND2_ITSELF],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线欺骗-无线网络中发送地址与接收地址相同\", \"%s\",\"接收的报文中，源地址与目的地址相同。\");",
		WIPS_EID_SEND2_ITSELF, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_SEND2_ITSELF].name);
	sprintf(cmd[WIPS_EID_AP_SIGNAL_TOOHIGH],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线欺骗-AP信号强度过高\",\"%s\", \"AP的信号强度超出正常值，可能干扰其他无线设备；同时也可能是恶意攻击者使用大功率的发射设备或大增益的天线。\");",
		WIPS_EID_AP_SIGNAL_TOOHIGH, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_AP_SIGNAL_TOOHIGH].name);
	sprintf(cmd[WIPS_EID_TOOMANY_AP_INACHANNEL],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线欺骗-同一信道中AP设备过多\",\"%s\", \"在同一信道中检测到的AP设备过多，超过门限值；同一信道中AP设备过多，会使干扰和冲突的发生概率增大，降低网络使用效率。\");",
		WIPS_EID_TOOMANY_AP_INACHANNEL, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_TOOMANY_AP_INACHANNEL].name);
	sprintf(cmd[WIPS_EID_ADHOC_SSID_AP_SSID_SAME],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-开启AdHoc的无线终端使用了AP的ESSID\",\"%s\", \"处于Ad Hoc工作模式的无线终端，使用了与某个合法AP相同的ESSID，会导致一些无线终端试图与其建立连接。\");",
		WIPS_EID_ADHOC_SSID_AP_SSID_SAME, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_ADHOC_SSID_AP_SSID_SAME].name);
//	sprintf(cmd[WIPS_EID_STA_FAKE_AS_AP],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线欺骗-无线终端使用了AP的MAC地址\", \"无线终端发送报文中的源地址与AP的地址相同。\");",
//		WIPS_EID_STA_FAKE_AS_AP, 0, WIPS_EID_SPOOFING_GRP);
	sprintf(cmd[WIPS_EID_STA_SIGNAL_TOOHIGH],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线欺骗-无线终端的信号强度过高\", \"%s\",\"无线终端的信号强度超出正常值，可能干扰其他无线设备；同时也可能是恶意攻击者使用大功率的发射设备或大增益的天线。\");",
		WIPS_EID_STA_SIGNAL_TOOHIGH, 0, WIPS_EID_SPOOFING_GRP,wips_event_table[WIPS_EID_STA_SIGNAL_TOOHIGH].name);


	sprintf(cmd[WIPS_EID_DOS_GRP],	GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线DOS攻击类\",\"%s\");", WIPS_EID_DOS_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_DOS_GRP].name);
	sprintf(cmd[WIPS_EID_DEAUTH_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线DoS攻击-去认证攻击\", \"%s\",\"无线网络中出现大量的由某个无线终端构造的去认证帧，通常这些去认证帧采用单播地址发给每个无线终端，也有可能被构造为发送给全部无线终端的广播地址，会引起AP上关联的无线终端被去关联。\");",
		WIPS_EID_DEAUTH_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_DEAUTH_STA].name);
	sprintf(cmd[WIPS_EID_MDK3_DEAUTH_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线DoS攻击-MDK3去认证攻击\",\"%s\", \"攻击者通过MDK3工具大量发送去认证报文，使得无线用户的合法接入遭到破坏，影响网络使用。\");",
		WIPS_EID_MDK3_DEAUTH_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_MDK3_DEAUTH_STA].name);
	sprintf(cmd[WIPS_EID_AIREPLAY_NG_DEAUTH_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"高\", \"无线DoS攻击-Aireplay-ng去认证攻击\",\"%s\", \"攻击者通过Aireplay-ng工具大量发送去认证报文，使得无线用户的合法接入遭到破坏，影响网络使用。\");",
		WIPS_EID_AIREPLAY_NG_DEAUTH_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_AIREPLAY_NG_DEAUTH_STA].name);
	sprintf(cmd[WIPS_EID_DEASSO_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-去关联攻击\",\"%s\",\"攻击者通过仿造无线客户地址大量发送去关联报文，使得无线用户的合法接入遭到破坏，影响网络使用。\");",
		WIPS_EID_DEASSO_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_DEASSO_STA].name);
	sprintf(cmd[WIPS_EID_MDK3_DEASSO_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-MDK3去关联攻击\",\"%s\", \"攻击者通过MDK3工具大量发送去关联报文，使得无线用户的合法接入遭到破坏，影响网络使用。\");",
		WIPS_EID_MDK3_DEASSO_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_MDK3_DEASSO_STA].name);
	sprintf(cmd[WIPS_EID_AUTH_FLOOD_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-认证帧泛洪攻击\",\"%s\", \"攻击者大量发送虚假的认证报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",
		WIPS_EID_AUTH_FLOOD_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_AUTH_FLOOD_STA].name);
	sprintf(cmd[WIPS_EID_ASSO_FLOOD_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-关联帧泛洪攻击\",\"%s\", \"攻击者大量发送虚假的关联报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",
		WIPS_EID_ASSO_FLOOD_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_ASSO_FLOOD_STA].name);
	sprintf(cmd[WIPS_EID_PROBE_FLOOD_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-探测帧泛洪攻击\",\"%s\", \"攻击者大量发送虚假的探测报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",
		WIPS_EID_PROBE_FLOOD_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_PROBE_FLOOD_STA].name);
	sprintf(cmd[WIPS_EID_ASSO_FLOOD_ACK_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-ACK泛洪攻击\",\"%s\", \"攻击者大量发送关联ACK报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",
		WIPS_EID_ASSO_FLOOD_ACK_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_ASSO_FLOOD_ACK_STA].name);
	sprintf(cmd[WIPS_EID_ASSO_FLOOD_RTS_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-RTS泛洪攻击\",\"%s\", \"在无线网络中的RTS报文超出门限值，大量RTS报文可能降低无线网络的性能和效率。\");",
		WIPS_EID_ASSO_FLOOD_RTS_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_ASSO_FLOOD_RTS_STA].name);
	sprintf(cmd[WIPS_EID_ASSO_FLOOD_CTS_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-CTS泛洪攻击\", \"%s\",\"攻击者大量发送关联CTS报文，使得无线接入点工作出现异常或网络繁忙，影响网络的正常使用。\");",
		WIPS_EID_ASSO_FLOOD_CTS_STA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_ASSO_FLOOD_CTS_STA].name);
	sprintf(cmd[WIPS_EID_DURATION_ATTACK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-时间片攻击\", \"%s\",\"无线终端发出的数据帧中，时间片字段设置大于上限，该时间用于更新无线网络中的网络分配向量（NAV），超过上限意味着该客户端要占用全部网络时间，时间值32768作为保留值用于在特定周期内发送。\");",
		WIPS_EID_DURATION_ATTACK, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_DURATION_ATTACK].name);
	sprintf(cmd[WIPS_EID_TOOMANY_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线DoS攻击-无线网络中AP过多\",\"%s\", \"检测到无线网络中AP数量过多，可能会造成相互干扰，并降低网络吞吐性能；也可能存在网络攻击行为。\");",
		WIPS_EID_TOOMANY_AP, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_TOOMANY_AP].name);
	sprintf(cmd[WIPS_EID_BRAODCAST_STORM],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线DoS攻击-无线网络中存在广播风暴\", \"%s\",\"在一段时间内，检测到无线网络中存在大量的广播报文，可能存在网络攻击行为；也有可能是网络配置存在严重的问题。\");",
		WIPS_EID_BRAODCAST_STORM, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_BRAODCAST_STORM].name);
	sprintf(cmd[WIPS_EID_BRAODCAST_SMAC],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线DoS攻击-无线源地址为广播地址\", \"%s\",\"无线终端使用全F的广播MAC地址作为其发送报文的源地址，这会导致对端在发送回应报文的时候，以广播的方式发送，可能造成严重的网络性能问题。\");",
		WIPS_EID_BRAODCAST_SMAC, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_BRAODCAST_SMAC].name);
	sprintf(cmd[WIPS_EID_GROUP_SMAC],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线DoS攻击-无线源地址为组播地址\",\"%s\", \"无线终端使用组播MAC地址（MAC地址第1字节的低位为1）作为其发送报文的源地址，这会导致对端在发送回应报文的时候，以组播的方式发送，可能造成严重的网络性能问题。\");",
		WIPS_EID_GROUP_SMAC, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_GROUP_SMAC].name);
	sprintf(cmd[WIPS_EID_AP_TOOMANY_QBSSSTA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线DoS攻击-AP的QBSS客户端过多\",\"%s\", \"一台开启了QBSS（Qos Basic Service Set）的AP上关联了过多的无线终端，过多采用QoS等级保证的用户和应用，会降低AP整体的性能。\");",
		WIPS_EID_AP_TOOMANY_QBSSSTA, 0, WIPS_EID_DOS_GRP,wips_event_table[WIPS_EID_AP_TOOMANY_QBSSSTA].name);


	sprintf(cmd[WIPS_EID_CRACK_GRP], GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线破解类\",\"%s\");", WIPS_EID_CRACK_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_CRACK_GRP].name);
	sprintf(cmd[WIPS_EID_VIOLENT_CRACK_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-无线暴力破解\",\"%s\", \"攻击者通过使用攻击字典进行暴力破解，试图获取无线用户接入网络的加密信息。\");",
		WIPS_EID_VIOLENT_CRACK_STA, 0, WIPS_EID_CRACK_GRP,wips_event_table[WIPS_EID_VIOLENT_CRACK_STA].name);
	sprintf(cmd[WIPS_EID_AIREPLAY_NG_FRAMG_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-Aireplay-ng_FRAMG破解\", \"%s\",\"Aireplay-ng属于Aircrack-ng工具集，是一款网络注入工具，专门密钥破解，包括FRAMG破解、CHOPCHOP破解、ARP注入等多种破解方式，Aireplay-ng FRAMG破解为其中一种。\");",
		WIPS_EID_AIREPLAY_NG_FRAMG_STA, 0, WIPS_EID_CRACK_GRP,wips_event_table[WIPS_EID_AIREPLAY_NG_FRAMG_STA].name);
	sprintf(cmd[WIPS_EID_AIREPLAY_NG_CHOP_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-Aireplay-ng_CHOPCHOP破解\", \"%s\",\"Aireplay-ng属于Aircrack-ng工具集，是一款网络注入工具，专门密钥破解，包括FRAMG破解、CHOPCHOP破解、ARP注入等多种破解方式，Aireplay-ng CHOPCHOP破解为其中一种。\");",
		WIPS_EID_AIREPLAY_NG_CHOP_STA, 0, WIPS_EID_CRACK_GRP,wips_event_table[WIPS_EID_AIREPLAY_NG_CHOP_STA].name);
	sprintf(cmd[WIPS_EID_AIREPLAY_NG_ARP_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-Aireplay-ng_ARP注入\", \"%s\",\"Aireplay-ng属于Aircrack-ng工具集，是一款网络注入工具，专门密钥破解，包括FRAMG破解、CHOPCHOP破解、ARP注入等多种破解方式，Aireplay-ng ARP注入为其中一种。\");",
		WIPS_EID_AIREPLAY_NG_ARP_STA, 0, WIPS_EID_CRACK_GRP,wips_event_table[WIPS_EID_AIREPLAY_NG_ARP_STA].name);
	sprintf(cmd[WIPS_EID_WESSID_NG_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-Wesside-ng_破解\", \"%s\",\"Wesside-ng是一个针对WEP加密的自动化破解工具, 集成了多种触发技术，使得WEP加密可以在几分钟之内被破解。\");",
		WIPS_EID_WESSID_NG_STA, 0, WIPS_EID_CRACK_GRP,wips_event_table[WIPS_EID_WESSID_NG_STA].name);
//	sprintf(cmd[WIPS_EID_ASLEAP_ATTACK],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-Asleap攻击\", \"Asleap是针对Leap认证进行破解的工具。\");",
//		WIPS_EID_ASLEAP_ATTACK, 0, WIPS_EID_CRACK_GRP);
	sprintf(cmd[WIPS_EID_8021XAUTH_ATTACK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线破解-802.1X暴力破解\",\"%s\", \"攻击者进行802.1X 用户名、密码 字典破解。\");",
		WIPS_EID_8021XAUTH_ATTACK, 0, WIPS_EID_CRACK_GRP,wips_event_table[WIPS_EID_8021XAUTH_ATTACK].name);


	sprintf(cmd[WIPS_EID_INFO_GRP],	GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线配置类\",\"%s\");", WIPS_EID_INFO_GRP, 1, WIPS_EID_ALL, wips_event_table[WIPS_EID_INFO_GRP].name);
	sprintf(cmd[WIPS_EID_ASSO_DENIED_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-AP拒绝终端的关联请求\",\"%s\",\"AP拒绝与某些STA关联，拒绝的原因包括：STA不符合802.11标准；AP已接入过多STA；STA不具备AP所要求的部分功能，如速率调整范围、PBCC调制功能等。\");",
		WIPS_EID_ASSO_DENIED_STA, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_ASSO_DENIED_STA].name);
	sprintf(cmd[WIPS_EID_AUTH_REFUSED],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-AP拒绝终端的认证请求\",\"%s\", \"AP拒绝无线终端的认证请求，当一个无线终端接入AP时，通常先发送探测请求，得到回应后，会发起认证过程，再进入关联过程。\");",
		WIPS_EID_AUTH_REFUSED, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AUTH_REFUSED].name);
	sprintf(cmd[WIPS_EID_AP_SMALL_FRAG_PKG],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线网络中分片报文过小\",\"%s\",\"网络中出现的分片报文过小，会降低无线网络吞吐性能，但会提升发送者的抗干扰能力。\");",
		WIPS_EID_AP_SMALL_FRAG_PKG, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AP_SMALL_FRAG_PKG].name);
//	sprintf(cmd[WIPS_EID_SMALL_INTERVAL_RETRY_PKG],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线网络中设备时间片过短\", \"802.11g设备发送重传时，使用短时间片，而802.11b设备不支持短时间片。在802.11b/g混合模式的网络中，这可能意味着存在网络冲突的问题。\");",
//		WIPS_EID_SMALL_INTERVAL_RETRY_PKG, 0, WIPS_EID_INFO_GRP);
	sprintf(cmd[WIPS_EID_TOOMANY_BEACON],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线网络中Beacon帧过多\",\"%s\", \"某个AP或Ad Hoc终端以较高的速率发送Beacon帧，并超过了门限值。\");",
		WIPS_EID_TOOMANY_BEACON, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_TOOMANY_BEACON].name);
	sprintf(cmd[WIPS_EID_REASSO_REFUSED],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-无线网络中重关联被拒绝\", \"%s\",\"AP拒绝无线终端的关联请求，无线终端通常的接入过程为：发送探测请求，接收探测回应，认证请求，认证回应，关联请求，关联回应。\");",
		WIPS_EID_REASSO_REFUSED, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_REASSO_REFUSED].name);
//	sprintf(cmd[WIPS_EID_SMALL_INTERVAL_RTS_CTS],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线网络中RTS/CTS数据报文过短\", \"RTS/CTS报文使用了过小的报文，可能影响网络吞吐性能。\");",
//		WIPS_EID_SMALL_INTERVAL_RTS_CTS, 0, WIPS_EID_INFO_GRP);
	sprintf(cmd[WIPS_EID_AP_ESSID_DIFF],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-AP存在不一致的配置\",\"%s\", \"在同一个ESSID中的多个AP（BSSID），采取了相互冲突或不一致的配置，例如不同的发射功率、速率配置、兼容性配置等。\");",
		WIPS_EID_AP_ESSID_DIFF, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AP_ESSID_DIFF].name);
	sprintf(cmd[WIPS_EID_AP_BG_MODE],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-AP工作在混合模式\", \"%s\",\"支持802.11b/g的AP同时与802.11b和802.11g的无线终端通信。\");",
		WIPS_EID_AP_BG_MODE, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AP_BG_MODE].name);
	sprintf(cmd[WIPS_EID_11N_DEVICE],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-AP开启了802.11n功能\",\"%s\", \"提示AP开启了802.11n功能。\");",
		WIPS_EID_11N_DEVICE, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_11N_DEVICE].name);
	sprintf(cmd[WIPS_EID_AP_SUPPORT40MHZ],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-AP开启了802.11n双信道绑定功能\",\"%s\", \"提示AP开启了802.11n的双信道绑定功能。\");",
		WIPS_EID_AP_SUPPORT40MHZ, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AP_SUPPORT40MHZ].name);
	sprintf(cmd[WIPS_EID_NO_QOS],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-AP未开启QoS功能\",\"%s\", \"AP未开启QoS或WMM功能。\");",
		WIPS_EID_NO_QOS, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_NO_QOS].name);
	sprintf(cmd[WIPS_EID_AP_SIGNAL_TOOLOW],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-AP信号强度过低\", \"%s\",\"AP发出报文的信号强度，在一段采样周期内的平均值低于门限值-96，该告警上报的次数取决于信号强度的采样周期，每个采样周期上报一次。\");",
		WIPS_EID_AP_SIGNAL_TOOLOW, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AP_SIGNAL_TOOLOW].name);
	sprintf(cmd[WIPS_EID_PROBE_NOAUTH],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-无线终端的探测请求未接受\",\"%s\", \"无线终端在发送探测请求、接收探测回应之后，未继续进行正常的关联过程。\");",
		WIPS_EID_PROBE_NOAUTH, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_PROBE_NOAUTH].name);
	sprintf(cmd[WIPS_EID_PROBE_REFUSED],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-无线终端的探测请求未回应\", \"%s\",\"AP未能针对无线终端探测其ESSID的探测请求发送回应消息。\");",
		WIPS_EID_PROBE_REFUSED, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_PROBE_REFUSED].name);
//	sprintf(cmd[WIPS_EID_ROAMING_BIG_INTERVAL],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线终端漫游时间过长\", \"在同一个无线网络中，无线终端从一台AP漫游到另一台漫游AP所花费的时间超过门限值5000毫秒。对时间敏感的应用例如语音、视频会因此受到影响。\");",
//		WIPS_EID_ROAMING_BIG_INTERVAL, 0, WIPS_EID_INFO_GRP);
	sprintf(cmd[WIPS_EID_STA_SMALL_FRAG_PKG],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线终端分片过多\", \"%s\",\"过多的报文被分片成更小的报文，通常会增大WLAN网络流量，降低吞吐性能。\");",
		WIPS_EID_STA_SMALL_FRAG_PKG, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_STA_SMALL_FRAG_PKG].name);
//	sprintf(cmd[WIPS_EID_STA_SLEEPING_BIG_INTERVAL],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线终端省电模式间隔超时\", \"在关联请求中定义了Beacon间隔的数值，空闲的无线终端会一直等待，直到接收下一次从AP发送来的数据。出现该事件时，表明无线终端未能及时被唤醒接收数据。\");",
//		WIPS_EID_STA_SLEEPING_BIG_INTERVAL, 0, WIPS_EID_INFO_GRP);
	sprintf(cmd[WIPS_EID_STA_LISTENINTERVAL_TOOBIG],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线终端省电模式侦听间隔过长\",\"%s\", \"无线终端进入省电模式的时间长于规定的门限值。\");",
		WIPS_EID_STA_LISTENINTERVAL_TOOBIG, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_STA_LISTENINTERVAL_TOOBIG].name);
//	sprintf(cmd[WIPS_EID_STA_SLEEPING_LOSE_PKG],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线终端省电模式丢包\", \"由于无线终端处于省电睡眠状态，AP丢弃了本应发给它的数据。\");",
//		WIPS_EID_STA_SLEEPING_LOSE_PKG, 0, WIPS_EID_INFO_GRP);
	sprintf(cmd[WIPS_EID_STA_SIGNAL_TOOLOW],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线配置-无线终端的信号强度过低\",\"%s\", \"无线终端发出报文的信号强度，在一段采样周期内的平均值低于门限值-96，该告警上报的次数取决于信号强度的采样周期，每个采样周期上报一次。\");",
		WIPS_EID_STA_SIGNAL_TOOLOW, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_STA_SIGNAL_TOOLOW].name);
//	sprintf(cmd[WIPS_EID_WINDOWS_AUTO_WIRELESS_CONFIG],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-无线终端使用不安全的默认Windows设置\", \"无线零配置。\");",
//		WIPS_EID_WINDOWS_AUTO_WIRELESS_CONFIG, 0, WIPS_EID_INFO_GRP);
	sprintf(cmd[WIPS_EID_AP_GN_MODE],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线配置-802.11g_802.11n混合模式\",\"%s\", \"ap同时支持G和N，当ap接入G模设备时将降低无线网络带宽。\");",
		WIPS_EID_AP_GN_MODE, 0, WIPS_EID_INFO_GRP,wips_event_table[WIPS_EID_AP_GN_MODE].name);


	sprintf(cmd[WIPS_EID_AUDIT_GRP], GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线审计类\",\"%s\");", WIPS_EID_AUDIT_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_AUDIT_GRP].name);
	sprintf(cmd[WIPS_EID_NEW_DEVICE_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-发现AP\",\"%s\", \"无线入侵防御系统发现新AP节点。\");",
		WIPS_EID_NEW_DEVICE_AP, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_NEW_DEVICE_AP].name);
	sprintf(cmd[WIPS_EID_NEW_DEVICE_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-发现无线终端\",\"%s\", \"无线入侵防御系统发现新STA节点。\");",
		WIPS_EID_NEW_DEVICE_STA, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_NEW_DEVICE_STA].name);
	sprintf(cmd[WIPS_EID_DEVICE_DOWN_AP],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-AP断电或离开\", \"%s\",\"曾经出现过的授权AP，最近一段时间却停止对外发送报文。该事件每个AP只上报一次，除非该AP又重新出现并消失，可能未AP断电或离开监控的区域。\");",
		WIPS_EID_DEVICE_DOWN_AP, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_DEVICE_DOWN_AP].name);
	sprintf(cmd[WIPS_EID_DEVICE_DOWN_STA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-终端断电或离开\", \"%s\",\"STA节点断电或离开。\");",
		WIPS_EID_DEVICE_DOWN_STA, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_DEVICE_DOWN_STA].name);
	sprintf(cmd[WIPS_EID_STA_ON_NETWORK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-终端接入无线网络\", \"%s\",\"客户端接入到新的无线网络。\");",
		WIPS_EID_STA_ON_NETWORK, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_STA_ON_NETWORK].name);
	sprintf(cmd[WIPS_EID_STA_OFF_NETWORK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-终端离开无线网络\",\"%s\", \"客户端离开当前已连接的无线网络。\");",
		WIPS_EID_STA_OFF_NETWORK, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_STA_OFF_NETWORK].name);
	sprintf(cmd[WIPS_EID_NOASSO_DATA],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线审计-无线网络中存在未关联的数据发送\", \"%s\",\"AP接收到未关联的无线终端发来的报文，AP通常会拒绝该报文，并向该无线终端发送包含错误状态码的去认证报文。\");",
		WIPS_EID_NOASSO_DATA, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_NOASSO_DATA].name);
	sprintf(cmd[WIPS_EID_AP_REBOOTED],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"信息\", \"无线审计-AP重启动\",\"%s\", \"AP在过去的几分钟之内发生重启；由于达到老化门限值或触发报文序列号统计事件。\");",
		WIPS_EID_AP_REBOOTED, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_AP_REBOOTED].name);
	sprintf(cmd[WIPS_EID_WIRELESS_MOOCH],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线审计-发现非正常工作时间段内的流量\", \"%s\",\"在用户定义的工作时间段之外，发现了无线终端的数据流量。\");",
		WIPS_EID_WIRELESS_MOOCH, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_WIRELESS_MOOCH].name);
	sprintf(cmd[WIPS_EID_SWITCH_ESSID],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线审计-无线终端切换无线网络\",\"%s\", \"无线终端切换到新网络，在不同网络中客户端的权限及其可用资源可能都不一样，用户可依此信息管理网络。客户端频繁切换网络是典型的非正常现象，有泄密风险。\");",
		WIPS_EID_SWITCH_ESSID, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_SWITCH_ESSID].name);
	sprintf(cmd[WIPS_EID_SWITCH_BSSID],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线审计-无线终端切换AP\", \"%s\",\"无线终端切换到新ap，可能是在fit_ap网络中发生了漫游，也可能是无线终端接入了钓鱼ap。\");",
		WIPS_EID_SWITCH_BSSID, 0, WIPS_EID_AUDIT_GRP,wips_event_table[WIPS_EID_SWITCH_BSSID].name);


	sprintf(cmd[WIPS_EID_INTERFERENCE_GRP], GRP_HEAD"(\"%d\", \"%d\", \"%d\", \"无线干扰类\",\"%s\");", WIPS_EID_INTERFERENCE_GRP, 1, WIPS_EID_ALL,wips_event_table[WIPS_EID_INTERFERENCE_GRP].name);
	sprintf(cmd[WIPS_EID_FREQ_HARDWARE_ERR],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络物理层错误\",\"%s\", \"在某个频段上，捕获的报文中包含CRC错误，且该错误报文超过门限值。\");",
		WIPS_EID_FREQ_HARDWARE_ERR, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_FREQ_HARDWARE_ERR].name);
	sprintf(cmd[WIPS_EID_FREQ_HARDWARE_ERR2OK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络物理层错误恢复\",\"%s\", \"无线干扰-无线网络物理层错误恢复。\");",
		WIPS_EID_FREQ_HARDWARE_ERR2OK, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_FREQ_HARDWARE_ERR2OK].name);
	sprintf(cmd[WIPS_EID_FREQ_OVERLAPPING],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络信道重叠\",\"%s\",\"在当前信道上检测到其它信道上的管理帧，表明存在信道重叠或信道泄漏。\");",
		WIPS_EID_FREQ_OVERLAPPING, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_FREQ_OVERLAPPING].name);
//	sprintf(cmd[WIPS_EID_SNR_TOOLOW],
//		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络中信噪比过低\", \"WIPS接收的无线报文的信噪比过低，低于门限值。\");",
//		WIPS_EID_SNR_TOOLOW, 0, WIPS_EID_INTERFERENCE_GRP);
	sprintf(cmd[WIPS_EID_INTERFERENCE],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络中存在射频干扰\",\"%s\",\"AP覆盖区域内出现干扰信号，对正常通信造成影响，导致无线带宽过低及无线重传次数大幅上升；并且此时网络中的平均信噪比低于所配置的门限值。\");",
		WIPS_EID_INTERFERENCE, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_INTERFERENCE].name);
	sprintf(cmd[WIPS_EID_INTERFERENCE_2OK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络中存在射频干扰恢复\",\"%s\", \"无线干扰-无线网络中存在射频干扰恢复。\");",
		WIPS_EID_INTERFERENCE_2OK, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_INTERFERENCE_2OK].name);
	sprintf(cmd[WIPS_EID_SUPPRESSION],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线干扰-无线网络中存在射频抑制\",\"%s\", \"无线射频抑制通常为恶意攻击，导致设备不能正常工作，该告警被触发时，信噪比低于所设定的门限值；射频抑制的风险高于射频干扰。\");",
		WIPS_EID_SUPPRESSION, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_SUPPRESSION].name);
	sprintf(cmd[WIPS_EID_SUPPRESSION_2OK],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"中\", \"无线干扰-无线网络中存在射频抑制恢复\", \"%s\",\"无线干扰-无线网络中存在射频抑制恢复。\");",
		WIPS_EID_SUPPRESSION_2OK, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_SUPPRESSION_2OK].name);
	sprintf(cmd[WIPS_EID_BITRATE_CHANGED],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络数据传输速率更改\",\"%s\", \"监测的报文中，协商速率低于之前的。\");",
		WIPS_EID_BITRATE_CHANGED, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_BITRATE_CHANGED].name);
	sprintf(cmd[WIPS_EID_RATESWITCH_TOOFAST],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线网络的数据传输速率多次更改\", \"%s\",\"多次改变协商的数据传输速率。\");",
		WIPS_EID_RATESWITCH_TOOFAST, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_RATESWITCH_TOOFAST].name);
	sprintf(cmd[WIPS_EID_AP_TOOMANY_RETRY],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-AP重传次数过多\",\"%s\", \"AP在一段之间之内多次发送无线报文，而未收到接收端的回应，重传的次数超过了门限值，每秒50次。\");",
		WIPS_EID_AP_TOOMANY_RETRY, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_AP_TOOMANY_RETRY].name);
	sprintf(cmd[WIPS_EID_STA_TOOMANY_RETRY],
		UNGRP_HEAD"(\"%d\", \"%d\", \"%d\", \"低\", \"无线干扰-无线终端重传次数过多\",\"%s\", \"无线终端尝试多次发送报文，但未得到ACK回应。\");",
		WIPS_EID_STA_TOOMANY_RETRY, 0, WIPS_EID_INTERFERENCE_GRP,wips_event_table[WIPS_EID_STA_TOOMANY_RETRY].name);

	for(i=1; i<= WIPS_EID_MAX; i++){
		sqlite3_exec(sql, cmd[i],NULL,NULL,NULL);
	}

	if(sql){
		wipsd_sqlite3_close(sql);
	}
}

static int init_database(void)
{

	int ret;
	sqlite3 *sql = NULL;
	char cmd[1024];

#if 0
	ret = sqlite3_open(DB_FILE,&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("sqlite open err !");
		return -1;
	}

	ret = -sqlite3_exec(sql,DROP_AP_LIST,NULL,NULL,NULL);
	ret = -sqlite3_exec(sql,CREATE_AP_LIST,NULL,NULL,NULL);

	ret = -sqlite3_exec(sql,DROP_STA_LIST,NULL,NULL,NULL);
	ret = -sqlite3_exec(sql,CREATE_STA_LIST,NULL,NULL,NULL);

	ret = -sqlite3_exec(sql,DROP_MANAGEMENT_LIST,NULL,NULL,NULL);
	ret = -sqlite3_exec(sql,CREATE_MANAGEMENT_LIST,NULL,NULL,NULL);

	if(sql){
		wipsd_sqlite3_close(sql);
	}
#endif

	if(!access(WIPS_LOG_DB,F_OK)) {
		ret = sqlite3_open(WIPS_LOG_DB, &sql);
		if(ret != SQLITE_OK){
			WIPSD_DEBUG("open sqlite table wips_log.db failed!");
			return -1;
		}

		ret = -sqlite3_exec(sql, "drop table wips_event", NULL, NULL, NULL);
		memset(cmd, 0 ,sizeof(cmd));
		sprintf(cmd,
			"create table wips_event( bssid nvarchar( 24 ), mac nvarchar( 24 ), channel varchar( 4 ),  "
			"ipaddr nvarchar( 16 ), vendor nvarchar(%d), alert nvarchar( 128 ), permit nvarchar(4), pri nvarchar(8), "
			" up_time TIMESTAMP default (datetime('now', 'localtime')), id nvarchar(4), is_grp nvarchar(4), grp_id nvarchar(4), "
			"detect_time nvarchar(28), name nvarchar( %d ), ssid nvarchar( %d ))",
			WEVENT_NAME_LEN, SSID_BUFSIZE_D, SSID_BUFSIZE_D);
		ret = -sqlite3_exec(sql, cmd, NULL, NULL, NULL);

        if(sql)
    		wipsd_sqlite3_close(sql);
	}

	//system("chmod 777 /usr/local/etc/wips/beacon_test.db");
	system("chmod 777 /usr/local/etc/wips/wconfig.db");
	system("chmod 777 /usr/local/etc/wips/wips_log.db");
	init_wevent();

	return 0;
}

void handle_signal(int s);
int read_log_config(void* data, int n_columns, char** column_values, char** column_names)
{

	//pthread_mutex_lock(&lock);
	if(column_values[0]){
		if(!strncmp(column_values[0], "all", 16))
			log_mode = 0;
		else if(!strncmp(column_values[0], "local", 16))
			log_mode = 1;
		else if(!strncmp(column_values[0], "remote", 16))
			log_mode =2;
		}
	//pthread_mutex_unlock(&lock);
	#if 0
	pthread_mutex_unlock(&lock);
	if(column_values[1])
		strncpy(&log_server_ip, column_values[1], 32);
	#endif
	return 0;
}

int get_log_config(void )
{
	sqlite3 *sql = NULL;
	int ret;

	ret = sqlite3_open("/usr/local/etc/wips/logconfig.db",&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite logconfig.db error !");
		return -1;
	}

	ret = -sqlite3_exec(sql, "select * from logconfig", read_log_config, NULL,NULL);

    if(sql)
    	wipsd_sqlite3_close(sql);

	return ret;
}

static inline void handle_sig_usr1(int signo){
	if(signo != SIGUSR1)
		return;
	//WIPSD_DEBUG("Handle sig usr1 \n");
	if(handle_flag){
		handle_flag = 0;
		get_log_config();
		handle_flag =1;
	}
	//WIPSD_DEBUG("log_mode = %d \n",log_mode);
	sleep(10);

	return;
}
void InitSignal(void)
{
	signal(SIGPIPE,handle_signal);
}

void handle_signal(int s)
{
	InitSignal();
}
#if 0
int get_obj_by_type(__u32 type, char **buf, int *len)
{
	struct cfg_req req;
	char *buf2 = NULL;
	int ret;
	int size = 8192;


	bzero(&req, sizeof(req));
	req.size = sizeof(struct cfg_req);
	req.obj_type = type;
	req.cmd_type = CMD_TYPE_SHOW;
	req.vsid = 0;

again:
	if (buf2)
		wipsd_free(buf2);
	size = size << 1;
	buf2 = malloc(size);
	if (buf2 == NULL)
		return -ERR_NOMEM;

	bzero(buf2, size);

	if ((ret = syscall(__NR_hls_config, &req, buf2, size)) < 0) {
		if (errno == ERR_BUFLACK)
			goto again;
		else
			goto error;
	}

	*buf = buf2;
	*len = ret;
	return ret;

error:
	wipsd_free(buf2);
	*buf = NULL;
	*len = 0;
	return -errno;
}
#endif
#if 0
int get_interface_info(void)
{

	char *getbuf;
	int getbuflen;
	const char cmd[128];
	const char cmd1[128];
	struct if_ether_obj *eths;
	int i, ret,found;

	found = 0;

	ret = get_obj_by_type(OBJ_TYPE_IF_ETHER, &getbuf, &getbuflen);
	if (ret < 0) {
		return ret;
	}

	eths = (struct if_ether_obj *)getbuf;

	for (i = 0; i < MAX_INTERFACE_NUM; i++) {
		if (!eths->eth[i].valid)
			continue;

		if (eths->eth[i].manage){
			found = 1;
			break;
			}
	}

	if(!found)
		i = 0;

	pthread_mutex_lock(&dev_lock);
	strncpy((char *)&interface_name, eths->eth[i].name, 16);
	pthread_mutex_unlock(&dev_lock);

	bzero((void *)cmd,sizeof(cmd));
	snprintf((char *)cmd , sizeof(cmd), "ifconfig | grep %s | awk '{print $5}'", (char *)&interface_name);

	bzero((void *)cmd1,sizeof(cmd1));
	snprintf((char *)cmd1 , sizeof(cmd1), "ifconfig %s | grep 'inet addr' | awk '{print $2}' | awk -F ':' '{print $2}'",(char *)&interface_name);

	pthread_mutex_lock(&dev_lock);
	lfd_get_dev_para((const char *)cmd, (char *)&dev_mac);
	lfd_get_dev_para((const char *)cmd1, (char *)&dev_ipaddr);
	pthread_mutex_unlock(&dev_lock);

	//WIPSD_DEBUG("dev_name = %s \n", interface_name);
	//WIPSD_DEBUG("dev_mac =%s \n", dev_mac);
	//WIPSD_DEBUG("dev_ipaddr = %s \n",&dev_ipaddr);

	wipsd_free(eths);
	return 0;
}

void *sig2_thread(void *arg)
{
	pthread_detach(pthread_self());

	if(handle_sig2){
		handle_sig2 = 0;
		get_interface_info();
		handle_sig2 = 1;
	}
	return NULL;
}
#endif
static int wipsd_init_itf_list(void)
{
	wipsd_itf_list = XMALLOC(MTYPE_TMP, sizeof(struct wipsd_interface_hdr));
	if(!wipsd_itf_list){
		WIPSD_DEBUG("Malloc memory for wipsd_itf_list failed!\t\n");
		return 1;
	}

	memset((void *)wipsd_itf_list, 0, sizeof(struct wipsd_interface_hdr));
	INIT_LIST_HEAD(&wipsd_itf_list->list);

	return 0;
}

static void wipsd_init_zebra(void)
{
	master = thread_master_create();
	if_init();
	zclient = zclient_new();
	zclient_init(zclient, ZEBRA_ROUTE_SYSTEM);
	vty_init();
}

static int wipsd_init_signal(void)
{
	signal_init();
	if (signal_set(SIGPIPE, SIG_IGN) == SIG_ERR)
		return 1;

	return 0;
}


int hanlde_kmaybe_nat(struct thread *th)
{
	int fd = THREAD_FD (th);
	int kpeerlen = sizeof(struct sockaddr_nl);
	int rcvlen;
	struct sockaddr_nl kpeer;
	struct u_packet_info
	{
	      struct nlmsghdr hdr;
	      struct net_sta_request p_info;
	}packet;
	int ret = 0;
	natfd_read_th=NULL;
	memset(&kpeer, 0, sizeof(kpeer));

	kpeer.nl_family = AF_NETLINK;

	kpeer.nl_pid = 0;

	kpeer.nl_groups = 0;
	/*接收内核空间返回的数据*/
	rcvlen = recvfrom(fd, &packet, sizeof(struct u_packet_info), 0, (struct sockaddr*)&kpeer, &kpeerlen);
	if(rcvlen>0)
	{
		struct w_node tmp;
		
		memset(&tmp,0,sizeof(struct w_node));
		tmp.node_type=0x1;
		tmp.nat_dev = 1;
		memcpy(tmp.bssid,(packet.p_info.mac_addr),6);
		memcpy(tmp.mac,(packet.p_info.mac_addr),6);
		snprintf(tmp.ssid,64,"[Rogue device based on NAT]");
		snprintf(tmp.name,64,"Rogue device based on NAT");

		{//add new node
		char mac_str[20];
		sprintf(mac_str,"%02x:%02x:%02x:%02x:%02x:%02x",
			tmp.mac[0],tmp.mac[1],tmp.mac[2],
			tmp.mac[3],tmp.mac[4],tmp.mac[5]);
		w_node_list * newnode= NULL;
		struct list_tast *mp=NULL;
		newnode = XMALLOC(MTYPE_WIPS_DEBUG_STA_NODE,sizeof(w_node_list));
		if(newnode == NULL){
			WIPSD_DEBUG("malloc for new wlist_node err!\n");
			return -1;
		}
		mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
		if(mp == NULL){
			WIPSD_DEBUG("malloc for new list_task err!\n");
			XFREE(MTYPE_WIPS_DEBUG_STA_NODE,newnode);
			return -1;
		}
		memset(mp,0,sizeof(struct list_tast));
		memset(newnode,0,sizeof(w_node_list));
		memcpy(&newnode->b_frame, &tmp, sizeof(struct w_node));
		strcpy( newnode->b_frame.vendor, P(find_mac_vendor(mac_str)));
		newnode->b_frame.refresh_time = newnode->b_frame.up_time = newnode->b_frame.last_time = fresh_time;
		newnode->b_frame.send_info_timeout = 0;
		mp->node = (void *)newnode;
		mp->task_type= LIST_TASK_ADD2APLIST;
		insertListTask(mp);

    	}
        
		task_stack();
	}

	if(!natfd_read_th){
		natfd_read_th = thread_add_read(master, hanlde_kmaybe_nat,NULL,maybe_net_fd);
		if(NULL == natfd_read_th )
			vsos_debug_out("there is already read fd[%d--%d]: rcvlen is %d, ret is %d\n",fd,maybe_net_fd,rcvlen,ret);
	}
	return 0;
}


int init_kmaybe_net(void)
{
	

	struct sockaddr_nl local;

	struct sockaddr_nl kpeer;
  	struct msg_to_kernel
	{
	      struct nlmsghdr hdr;
	}message;
	maybe_net_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_KMAY_NET);
	if(maybe_net_fd < 0)
	{
		vsos_debug_out("can not create a netlink socket\n");
		exit(0);

	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();          /*设置pid为自己的pid值*/
	local.nl_groups = 0;
	if(bind(maybe_net_fd, (struct sockaddr*)&local, sizeof(local)) != 0)
	{
		vsos_debug_out("bind() error\n");
		return -1;
	}

	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;

	memset(&message, 0, sizeof(message));
	message.hdr.nlmsg_len = NLMSG_LENGTH(0);
	message.hdr.nlmsg_flags = 0;
	message.hdr.nlmsg_type = MSG_USER_PID;     /*设置自定义消息类型*/
	message.hdr.nlmsg_pid = local.nl_pid;         /*设置发送者的PID*/
	sendto(maybe_net_fd, &message, message.hdr.nlmsg_len, 0, (struct sockaddr*)&kpeer, sizeof(kpeer));
	natfd_read_th = thread_add_read(master, hanlde_kmaybe_nat,NULL,maybe_net_fd);
	return 0;

}

static int wipsd_rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	socklen_t addr_len;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rth->fd < 0) {
		vsos_debug_out("Cannot open netlink socket");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		vsos_debug_out("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		vsos_debug_out("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		vsos_debug_out("Wrong address length %d", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		vsos_debug_out("Wrong address family %d", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
    
	return 0;
}

static int wipsd_rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.g.rtgen_family = family;

	return sendto(rth->fd, (void*)&req, sizeof(req), 0, (struct sockaddr*)&nladdr, sizeof(nladdr));
}

static int wipsd_parse_arp_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	if (NULL == tb || NULL == rta)
    {
		vsos_debug_out("%s-%d:\n", __func__, __LINE__);
		return -1;
	}
	
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    
	while (RTA_OK(rta, len))
    {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
        
		rta = RTA_NEXT(rta,len);
	}
    
	if (len)
    {
		vsos_debug_out("%s-%d:len=%d, rta_len=%d\n", __func__, __LINE__, len, rta->rta_len);
	}
    
	return 0;
}

int wipsd_handle_arp_msg(struct nlmsghdr *arpmsg) 
{
	struct ndmsg *arp_data = NULL;
    struct rtattr * tb[NDA_MAX+1];
	unsigned char *lladdr = NULL;
	int len = 0;	

	if (NULL == arpmsg)
    {
		vty_print_std("%s-%d:arpmsg is null\n", __func__, __LINE__);
		return -1;
	}

	if (arpmsg->nlmsg_type != RTM_NEWNEIGH)
    {
		//vty_print_std("%s-%d:nlmsg_type=%d is not RTM_NEWNEIGH(%u)\n", __func__, __LINE__, arpmsg->nlmsg_type, RTM_NEWNEIGH);
		return -1;
	}

	arp_data = NLMSG_DATA(arpmsg);
	len = arpmsg->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*arp_data));
	if (len < 0)
    {
		vty_print_std("%s-%d: nlmsg len %d\n", __func__, __LINE__,len);
		return -1;
	}

	if (AF_INET != arp_data->ndm_family)
    {
		vty_print_std("%s-%d: ndm_family(%d)is not AF_INET\n", __func__, __LINE__,arp_data->ndm_family);
		return -1;
	}

	wipsd_parse_arp_rtattr(tb, NDA_MAX, NDA_RTA(arp_data), len);

	if (!tb[NDA_LLADDR]) 
        return -1;
    
    lladdr = (unsigned char *)RTA_DATA(tb[NDA_LLADDR]);
    if (!lladdr)
    {
        vty_print_std("%s-%d:lladdr is NULL!\n", __func__, __LINE__);
        return -1;
    }

    struct w_node_list * tmp=NULL;
    tmp = (w_node_list * )hash_find(wlist_hash_table, (const char *)lladdr, 6);
    if ((!tmp) || !(tmp->b_frame.node_type & 0x2))
    {
    //    vty_print_std("%s-%d:can't find sta mac="NMACQUAD_FMT"\n", __func__, __LINE__, NMACQUAD(lladdr));
        return 0;
    }

 //   vty_print_std("%s-%d:mac="NMACQUAD_FMT" is_arp_added\n", __func__, __LINE__, NMACQUAD(lladdr));

    tmp->b_frame.is_arp_added = 1;

#if 0
    char *ip=NULL;
    char mac_str[20];
    sprintf(mac_str, MACSTR, MAC2STR(tmp->b_frame.bssid));
    find_lan_ip(mac_str, &ip);
    if(ip)
    {
        clear_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
        XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
        return 0;
    }
    
    tmp = (w_node_list * )hash_find(wlist_hash_table, (const char *)tmp->b_frame.bssid, 6);
    if ((!tmp) || !(tmp->b_frame.node_type & 0x1))
    {
        vty_print_std("%s-%d:can't find mac="NMACQUAD_FMT" bssid="NMACQUAD_FMT"\n", __func__, __LINE__, NMACQUAD(tmp->b_frame.mac), NMACQUAD(tmp->b_frame.bssid));
        return 0;
    }
    
    if (tmp->b_frame.internal_node != TRUE)
    {
        vty_print_std("%s-%d:bssid="NMACQUAD_FMT"\n", __func__, __LINE__, NMACQUAD(tmp->b_frame.bssid));
        clear_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
        report_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
    }
#endif
	return 0;
}


int hanlde_arp_event(struct thread *th)
{
	int fd = THREAD_FD (th);
	int nbyte = 0;
	struct nlmsghdr *arpmsg = NULL;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	char buf[8192] = {0};

	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;	
	iov.iov_len = sizeof(buf);

	nbyte = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (nbyte <= 0)
    {
		vty_print_std("%s-%d: recvmsg failed: %s, fd(%d)", __func__, __LINE__, strerror(errno), fd);
		goto out;
	}

	for (arpmsg = (struct nlmsghdr*)buf; nbyte >= sizeof(*arpmsg);)
    {
		int err = 0;
		int len = arpmsg->nlmsg_len;
		int l = len - sizeof(*arpmsg);

		if (l < 0 || len > nbyte)
        {
			vty_print_std("%s-%d: len=%d, nbtye=%d, sizeof(buf)=%ld\n", __func__, __LINE__, len, nbyte, sizeof(*arpmsg));
			return -1;
		}

		err = wipsd_handle_arp_msg(arpmsg);
		if (err < 0)
			goto out;
		
		nbyte -= NLMSG_ALIGN(len);
		arpmsg = (struct nlmsghdr*)((char*)arpmsg + NLMSG_ALIGN(len));
	}

out:
    thread_add_read(master, hanlde_arp_event, NULL, rth.fd);
    
	return 0;
}

int init_arp_event(void)
{
	if (wipsd_rtnl_open(&rth, RTMGRP_NEIGH) < 0)
    {
		vty_print_std("wipsd_rtnl_open failed\n");
		return -1;
	}

    wipsd_rtnl_wilddump_request(&rth, AF_INET, RTM_GETNEIGH);
    
    thread_add_read(master, hanlde_arp_event, NULL, rth.fd);

    return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	char ssid_filename[255];
	FILE * ssid_fp =0;
	u32 run_daemon = 0;
	int option;
	char TMP_IP[28];
	char PORT[28];
	struct thread thread;

	while ((option = getopt(argc, argv, "i:f:I:P:l:d")) != EOF){
		switch (option){
			case 'f' :
				memset ((void *)ssid_filename,0,sizeof(ssid_filename));
				strncpy (ssid_filename, optarg,sizeof(ssid_filename)-1);
				WIPSD_DEBUG("ssid_filename = %s\n",ssid_filename);
				f_enable =1;
				break;
			case 'i':
				memset((void *)iface, 0, sizeof(iface));
				strncpy((void *)iface, (void *)optarg, sizeof(optarg));
				break;
			case 'I' :
				memset((void *)TMP_IP,0,sizeof(TMP_IP));
				strncpy((void *)TMP_IP, (void *)optarg, sizeof(optarg));
				AC_ip = (char *)TMP_IP;
				WIPSD_DEBUG("server_IP = %s\n",AC_ip);
				//ppclient_enable++;
				break;
			case 'P' :
				memset ((void *)PORT,0,sizeof(PORT));
				strncpy (PORT, optarg,sizeof(PORT)-1);
				AC_port = atoi(PORT);
				WIPSD_DEBUG("server_PORT = %d\n",AC_port);
				//ppclient_enable++;
				break;
			case 'l':
				suspend_package_num = atoi(optarg);
				WIPSD_DEBUG("suspend_package_num = %d\n",suspend_package_num);
				break;
			case 'd':
				run_daemon = 1;
				break;
			default :
				break;
		} // End of switch
	} // End of while


#ifdef MEMORY_ENABLED
	memory_init();
#endif

	ret = wipsd_init_signal();
	if(ret) {
		WIPSD_DEBUG("wipsd_init_signal(), err %d!\t\n", ret);
		return 0;
	}

#ifdef SYSLOG_ENABLE
	//init_timer(0, 0);
	openlog((char *)wips_dm[EVENT].keyword, 0, (int)wips_dm[EVENT].fac);
#endif

	w_tmp = malloc(sizeof(struct w_node));
	if(!w_tmp ){
		WIPSD_DEBUG("main malloc err! exit. \n");
		return 0;
	}
	memset(w_tmp,0,sizeof(struct w_node));
	w_tmp->node_type = 0x01;

	if(f_enable){
		int i=0;
		if ((ssid_fp = fopen(ssid_filename,"r")) == NULL){
			WIPSD_DEBUG("Error, could not open file %s\n", ssid_filename);
			exit (EXIT_FAILURE);
		}

		while (count < MAXLINES && fgets (ssidlist[count], IW_ESSID_MAX_SIZE, ssid_fp) != NULL){
			// Remove newlines
			ssidlist[count][strlen(ssidlist[count])-1] = '\0';
			count++;
		}

		fclose(ssid_fp);
		hotspot_hash_table = hash_new();
		if (!hotspot_hash_table)
			WIPSD_DEBUG("hash_new failed");

		for(i =0; i<count; i++){
			hash_insert(hotspot_hash_table, (const char *)ssidlist[i], 0,
				(void *)ssidlist[i]);
		}
	}

	ret = init_database();
	if (ret){
		WIPSD_DEBUG("init_database failed(%d)!\n",ret);
		return 0;
	}

	init_channel_blacklist();

	ret = init_wevent_list();
	if(ret){
		WIPSD_DEBUG("init_wevent_list failed(%d)!\n",ret);
		return 0;
	}

	log_mode = 0;//default event log: local log

	ret = init_vendor_hash_table();
	if(ret){
		WIPSD_DEBUG("init_vendor_hash_table failed(%d)!\n",ret);
		return 0;
	}

	ret = init_wlist_hash_table();
	if(ret){
		WIPSD_DEBUG("init_wlist_hash_table failed(%d)!\n",ret);
		return 0;
	}

	ret = init_essid_hash_table();
	if(ret){
		WIPSD_DEBUG("init_essid_hash_table failed(%d)!\n",ret);
		return 0;
	}

	ret = init_ctime_hash_table();
	if(ret){
		WIPSD_DEBUG("init_ctime_hash_table failed(%d)!\n",ret);
		return 0;
	}

	ret = init_subnet_hash(WIPS_WCONFIG_DB);
	if(ret){
		WIPSD_DEBUG("init_subnet_hash failed(%d)!\n",ret);
		return 0;
	}

	ret = init_wgate_hash(WIPS_WCONFIG_DB);
	if(ret){
		WIPSD_DEBUG("init_wgate_hash failed(%d)!\n",ret);
		return 0;
	}

	ret = dobj_wgate_init();
	if(ret){
		WIPSD_DEBUG("dobj_wgate_init failed(%d)!\n",ret);
		return 0;
	}

#ifdef MEMLOG
	init_event_memlog();
#else
	ret = init_event_sqllog(WIPS_LOG_DB);
	if(ret){
		WIPSD_DEBUG("init_event_sqllog failed(%d)!\n",ret);
		return 0;
	}
#endif

	init_pollnode();
	init_block_table();
	ret = wipsd_init_itf_list();
	if(ret){
		WIPSD_DEBUG("wipsd_init_itf_list failed(%d)!\n",ret);
		return -1;
	}

	wipsd_init_zebra();
	wipsd_if_register();
	wipsd_init_vty();
	init_kmaybe_net();
    init_arp_event();
	vty_serv_sock(NULL, 0, WIPSD_PATH);
	time((time_t *)&fresh_time);
	if(run_daemon)
	{
		ret = daemon(0, 0);
		if(ret)
		{
			WIPSD_DEBUG("daemon(), err %d!\t\n", ret);
			return 0;
		}
	}

	while (thread_fetch (master, &thread)){
		thread_call (&thread);
	}

	WIPSD_DEBUG("wipsd quit!\n");

	return 0;
}

