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
#include "wipsd_wnode.h"
//#include "checklist.h"
#include "wipsd_hook.h"

//static bwlist_node *list_hdr = NULL;
#define MAX_CHAR_NUM 256
#define CMP_OK 0
#if 0
#else
/* A hash table.  */
struct hash_control {
  /* The hash array.  */
  struct hash_entry **table;
  /* The number of slots in the hash table.  */
  unsigned int size;
  /* An obstack for this hash table.  */
  struct obstack memory;

#ifdef HASH_STATISTICS
  /* Statistics.  */
  unsigned long lookups;
  unsigned long hash_compares;
  unsigned long string_compares;
  unsigned long insertions;
  unsigned long replacements;
  unsigned long deletions;
#endif /* HASH_STATISTICS */
};
extern struct hash_control *nodeinfo_hash_table;
#endif

extern long fresh_time;
extern struct w_node *w_tmp;
extern int heardaddr;
extern int fcs;
extern long SINGLE;
extern long NOISE ;
extern long CHANNEL ;
extern long RATE ;
int event_count(int * count,int c_max, int * interval, int inter_max);
int get_wlist_node(char * mac, struct w_node ** node_frame);
void str2mac(__u8 * mac, char * str1);
int report_wips_event(struct w_node *node, int event);
__u32 test_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] );
int clear_wips_event(struct w_node *node, int event);

struct hash_control *node_essid_hash_table;
#define OBJECT_MAX_NUM 500

int average_event_count(int * count, int * cum, int * average, 
	int data, int * interval, int inter_max)
{
	int state=0;
	int ave_tmp=0;

	if( fresh_time < *interval + inter_max){
		*count += 1;
		*cum += data;
	}else{
		*count += 1;
		*cum += data;
		ave_tmp = *cum / *count;
		if( ave_tmp < *average){
			state = 1;
		}else if( ave_tmp > *average){
			state = 2;
		}else{
			state = 3;
		}
		*count = 0;
		*cum = 0;
		*average = ave_tmp;
		*interval = fresh_time;
	}
	return state;
}

int read_aplist_config(void* data, int n_columns, char** column_values, 
	char** column_names)
#if 0
{}
#else
{
	nodeInfo_exec_hook_para *sql_para = (nodeInfo_exec_hook_para *)data;
	nodeInfo *node;
	int * i;
	if(!sql_para)return -1;
	node = sql_para->node;
	i = sql_para->i;

	if((*i) < OBJECT_MAX_NUM){}else{return 0;}
	if(column_values[4]){
		if(column_values[0]){
			strncpy( node[(*i)].name, column_values[0],sizeof(node[(*i)].name)-1);
		}
		if(column_values[2]){
			strncpy( node[(*i)].ipv4, column_values[2],sizeof(node[(*i)].ipv4)-1);
		}
		str2mac(node[(*i)].mac, column_values[4]);
		node[(*i)].node_type = 0x1;
		if(column_values[1]){
			if(strncmp(column_values[1], "internalap", 2)==0){
				node[(*i)].node_type |= 0x80;
			}else if(strncmp(column_values[1], "rogueap", 2)==0){
				node[(*i)].node_type |= 0x100;
			}
		}
		if( hash_insert(nodeinfo_hash_table, (const char *)node[(*i)].mac, 6, 
		(void *)&node[(*i)]) == NULL){
			(*i)++;
		}
	}

	return 0;
}
#endif
int read_stalist_config(void* data, int n_columns, char** column_values, char** column_names)
#if 0
{}
#else
{
	nodeInfo_exec_hook_para *sql_para = (nodeInfo_exec_hook_para *)data;
	nodeInfo *node;
	int * i;
	if(!sql_para)return -1;
	node = sql_para->node;
	i = sql_para->i;

	if((*i) < OBJECT_MAX_NUM){}else{return 0;}
	if(column_values[1]){
		if(column_values[0]){
			strncpy( node[(*i)].name, column_values[0],sizeof(node[(*i)].name)-1);
		}
		str2mac(node[(*i)].mac, column_values[1]);
		node[(*i)].node_type = 0x2;
		if( hash_insert(nodeinfo_hash_table, (const char *)node[(*i)].mac, 6, 
		(void *)&node[(*i)]) == NULL){
			(*i)++;
		}
	}

	return 0;
}
#endif
int read_iplist_config(void* data, int n_columns, char** column_values, char** column_names)
#if 0
{}
#else
{
	nodeInfo_exec_hook_para *sql_para = (nodeInfo_exec_hook_para *)data;
	nodeInfo *node;
	nodeInfo *tmp=NULL;
	int * i;
	if(!sql_para)return -1;
	node = sql_para->node;
	i = sql_para->i;

	if((*i) < OBJECT_MAX_NUM){}else{return 0;}
	if(column_values[1]){
		if(column_values[2]){
			strncpy( node[(*i)].ipv4, column_values[2],sizeof(node[(*i)].ipv4)-1);
		}
		str2mac(node[(*i)].mac, column_values[1]);
		if( hash_insert(nodeinfo_hash_table, (const char *)node[(*i)].mac, 6, 
		(void *)&node[(*i)]) == NULL){
			(*i)++;
		}else{
			tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, 
				(const char *)node[(*i)].mac, 6);
			if(tmp){
				memcpy(tmp->ipv4, node[(*i)].ipv4, sizeof(node[(*i)].ipv4));
			}else{
				WIPSD_DEBUG("add_wlistnode: find a NULL point from hashTable!\n");
			}
		}
	}

	return 0;
}
#endif

int update_nodeinfo_list(void)
#if 0
{}
#else
{
	static nodeInfo node[OBJECT_MAX_NUM];
	int i=0;
	static essidObject essid_obj[OBJECT_MAX_NUM];
	int essid_obj_num=0;
	unsigned long alloc;
	
	sqlite3 *sql = NULL;
	int ret;

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("[%s]open sqlite wconfig.db error !\n", __FUNCTION__);
		return -1;
	}

	alloc = nodeinfo_hash_table->size;
	alloc = alloc * sizeof(struct hash_entry *);
	memset (nodeinfo_hash_table->table, 0, alloc);
	
	alloc = node_essid_hash_table->size;
	alloc = alloc * sizeof(struct hash_entry *);
	memset (node_essid_hash_table->table, 0, alloc);
	
	memset (node, 0, OBJECT_MAX_NUM*sizeof (nodeInfo));
	memset (essid_obj, 0, OBJECT_MAX_NUM*sizeof (essidObject));
	
	nodeInfo_exec_hook_para sql_para, essid_para;
	sql_para.node = node;
	sql_para.i = &i;
	essid_para.node = essid_obj;
	essid_para.i = &essid_obj_num;

	ret = -sqlite3_exec(sql, "select * from aplist where wmac!=\"\"", read_aplist_config, &sql_para,NULL);
	ret = -sqlite3_exec(sql, "select * from stalist where mac!=\"\"", read_stalist_config, &sql_para,NULL);
	ret = -sqlite3_exec(sql, "select * from wnet", read_ap_essid, &essid_para,NULL);

    if(sql)
    	wipsd_sqlite3_close(sql);

if(0){
	ret = sqlite3_open("/usr/hls/log/log/hosts.db",&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite hosts.db error !");
		return -1;
	}
	ret = -sqlite3_exec(sql, "select * from ip", read_iplist_config, &sql_para,NULL);
    if(sql)
    	wipsd_sqlite3_close(sql);
}
	
	return ret;
}
#endif

int check_adhoc_ap_ssid(struct w_node * node_frame, int initch)
{
	static char adhocssid[10][SSID_BUFSIZE_D];
	static int i=0;
	int j;

	if(initch){
		memset(adhocssid, 0, sizeof(adhocssid));
		i=0;
		return 0;
	}
	if(!node_frame)return 0;

	if(node_frame->node_type & 4){
		for(j=0;j<i;j++){
			if(memcmp( &adhocssid[j],node_frame->ssid,SSID_BUFSIZE_D) == 0){
				return 0;
			}
		}
		if(i<10){
			memcpy(&adhocssid[i], node_frame->ssid, SSID_BUFSIZE_D);
			i++;
		}
	}else if(node_frame->node_type & 1){
		for(j=0;j<i;j++){
			if(memcmp( &adhocssid[j],node_frame->ssid,SSID_BUFSIZE_D) == 0){
				return 1;
			}
		}
	}

	return 0;
}

int check_ap_essid_seting(struct w_node * node_frame, int initch)
{
	static struct w_node * node[200];
	struct w_node * tmp= NULL;
	static int i=0;
	int j;

	static int here=1,hero=1;
	if(hero){
		hero = 0;
		j = system("date >> /tmp/essid_seting");
		j = system("echo check_ap_essid_seting in... >> /tmp/essid_seting");
		WIPSD_DEBUG("check_ap_essid_seting in...\n");
	}

	if(initch){
		memset(node, 0, sizeof(node));
		i=0;
		return 0;
	}
	if(!node_frame)return 0;
	
	if(here){
		char cmd[100];
		here = 0;
		j = system("date >> /tmp/essid_seting");
		sprintf(cmd, "echo \"node_frame->node_type[%d]\" >> /tmp/essid_seting\n", node_frame->node_type);
		j = system(cmd);
		WIPSD_DEBUG("check_ap_essid_seting node_frame->node_type[%d]\n", node_frame->node_type);
	}
	return 0;

	for(j=0;j<i;j++){
		tmp = node[j];
		if(tmp){
			if(memcmp( tmp->ssid,node_frame->ssid,SSID_BUFSIZE_D) == 0){
				if(memcmp( tmp->sec_type,node_frame->sec_type,sizeof(node_frame->sec_type)) == 0){
					return 0;
				}else{
					return 1;
				}
			}
		}
	}
	if(i<200){
		node[i] = node_frame;
		i++;
	}

	return 0;
}

int check_apnumber_eachchannel(__u16 channel, int initch)
{
	static int ch[CHANNEL_MAX_5G];

	if(initch){
		memset(ch, 0, CHANNEL_MAX_5G);
		return 0;
	}

	ch[channel]++;

	if(ch[channel] > 30) return 1;
	return 0;
}

int check_default_ssid(char * ssid)
{
	if(strncmp(ssid, "tp-link_", 8) == 0){
		return 1;
	}
	if(strncmp(ssid, "Tp-link_", 8) == 0){
		return 1;
	}
	if(strncmp(ssid, "TP-LINK_", 8) == 0){
		return 1;
	}
	if(strncmp(ssid, "D-LINK_", 7) == 0){
		return 1;
	}
	if(strncmp(ssid, "D-link_", 7) == 0){
		return 1;
	}
	if(strncmp(ssid, "d-link_", 7) == 0){
		return 1;
	}
	
	return 0;
}

void init_channel_blacklist(void)
{
	int i;
	check_channel_blacklist(NULL, NULL,1, 0, 0);
	for(i=1; i<14; i++)
		check_channel_blacklist(NULL, NULL,0, 0, i);
	
	for(i=149; i<166; i+=4)
		check_channel_blacklist(NULL, NULL,0, 0, i);

}

void check_channel_blacklist(struct w_node * latest,struct w_node * exist,
			int initlist, int forbidchannel, int enablechannel)
{
	static __u8 blacklist[249];

	if(initlist){
		memset(blacklist,1,249);
		return;
	}
	if(forbidchannel){
		blacklist[forbidchannel] = 1;
	}
	if(enablechannel){
		blacklist[enablechannel] = 0;
	}
	if(latest && exist){
		if( 0 < latest->channel && latest->channel < 249 && blacklist[latest->channel]){
			//printf("WIPS_EID_FORBID_CHANNEL\n");
			report_wips_event(exist, WIPS_EID_FORBID_CHANNEL);
		}
	}

}

void check_bitrate_blacklist(struct w_node * latest,struct w_node * exist,
			int initlist, int forbidrate, int enablerate)
#if 1
{}
#else
{
	static __u8 blacklist[610];

	if(initlist){
		memset(blacklist,0,610);
		return;
	}
	if(forbidrate){
		blacklist[forbidrate] = 1;
	}
	if(enablerate){
		blacklist[enablerate] = 0;
	}
	if(latest && exist){
		if(latest->rates < 610 && blacklist[latest->rates]){
			nodeInfo *tmp=NULL;
			tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, 
							(const char *)latest->mac, 6);
			if(!tmp || !(tmp->node_type & 0x40)){
				if(exist->node_type & 1){
			//printf("WIPS_EID_AP_FORBIDRATE\n");
					report_wips_event(exist, WIPS_EID_AP_FORBIDRATE);
				}else if(exist->node_type & 2){
			//printf("WIPS_EID_STA_FORBIDRATE\n");
					report_wips_event(exist, WIPS_EID_STA_FORBIDRATE);
				}
			}
		}
	}

}
#endif
#define NMACQUAD_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define NMACQUAD(addr) \
       ((unsigned char *)addr)[0], \
       ((unsigned char *)addr)[1], \
       ((unsigned char *)addr)[2], \
       ((unsigned char *)addr)[3], \
       ((unsigned char *)addr)[4], \
       ((unsigned char *)addr)[5] 

void check_auth_device(struct w_node * latest,struct w_node * exist)
#if 0
{}
#else
{
	nodeInfo *tmp = NULL;
	struct w_node *node;
	tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, 
					(const char *)exist->mac, 6);

	if(exist->node_type & 1 && (exist->ipv4[0] != '\0')){
		if(!tmp || tmp->node_type & 0x100){
            WIPSD_DEBUG("%s-%d: report_wips_event WIPS_EID_UNAUTH_AP\n", __func__, __LINE__);
			report_wips_event(exist, WIPS_EID_UNAUTH_AP);
		}else{
			clear_wips_event(exist, WIPS_EID_UNAUTH_AP);
            clear_wips_event(exist, WIPS_EID_FISHING_AP);
            clear_wips_event(exist, WIPS_EID_STA_PROXY_AP);
		}
		if(exist->node_type == 1)
			return ;
	}

	if(!tmp){
		//unauth
		report_wips_event(exist, WIPS_EID_UNAUTH_STA);
/*		goto INTERNAL_AP;
	}else if(!(tmp->node_type & 0x40)){
		//unauth
		report_wips_event(exist, WIPS_EID_UNAUTH_STA);
INTERNAL_AP:*/
		//printf("WIPS_EID_UNAUTH_STA\n");
		if(0 == get_wlist_node((char *)exist->bssid, &node)){
			if( node->internal_node == TRUE){
				//printf("WIPS_EID_UNAUTHSTA_INTERAP\n");
				clear_wips_event(exist, WIPS_EID_UNAUTHSTA_INTERAP);
				report_wips_event(exist, WIPS_EID_UNAUTHSTA_INTERAP);
			}
		}
	}else{
		clear_wips_event(exist, WIPS_EID_UNAUTH_STA);
		if(0 == get_wlist_node((char *)exist->bssid, &node)){
			if(test_wevent_bitmap(WIPS_EID_UNAUTH_AP, &node->alert)){
			//printf("WIPS_EID_AUTHSTA_UNAUTHAP\n");
    			clear_wips_event(exist, WIPS_EID_AUTHSTA_UNAUTHAP);
				report_wips_event(exist, WIPS_EID_AUTHSTA_UNAUTHAP);
			}
			if( node->internal_node == FALSE ){
				//printf("WIPS_EID_UNAUTHSTA_INTERAP\n");
				clear_wips_event(exist, WIPS_EID_AUTHSTA_EXTAP);
				report_wips_event(exist, WIPS_EID_AUTHSTA_EXTAP);
			}
		}
	}
}
#endif

int maybe_fishing_ap(struct w_node * exist)
{
	nodeInfo *tmp = NULL;
	tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, 
					(const char *)exist->mac, 6);
	if(!tmp){
		return 1;
	}else{
		if(!(tmp->node_type & 0x180)){
			return 1;
		}
	}

	return 0;
}

void check_address(struct w_node * latest,struct w_node * exist)
{
	if(memcmp( latest->mac,latest->dstmac,6) == 0){
		//printf("WIPS_EID_SEND2_ITSELF\n");
		report_wips_event(exist, WIPS_EID_SEND2_ITSELF);
	}
	if(memcmp( latest->mac,"\xff\xff\xff\xff\xff\xff",6) == 0){
		//printf("WIPS_EID_BRAODCAST_SMAC\n");
		report_wips_event(exist, WIPS_EID_BRAODCAST_SMAC);
	}else if(latest->mac[0] & 0x01){
		//printf("WIPS_EID_GROUP_SMAC\n");
		report_wips_event(exist, WIPS_EID_GROUP_SMAC);
	}
}

void check_lsatpkgtype(struct w_node * latest,struct w_node * exist, int pkgtype)
{
	if(exist->node_type & 0x02){
		switch(pkgtype){
			case WIPS_PKGTYPE_DATA:
				if(exist->last_pkg_type == WIPS_PKGTYPE_DEAUTH){
					//printf("WIPS_EID_NOASSO_DATA\n");
					report_wips_event(exist, WIPS_EID_NOASSO_DATA);
				}
				break;
			default :
				break;
		}
		exist->last_pkg_type = pkgtype;
	}
}

void check_bitrate(struct w_node * latest,struct w_node * exist)
{
	int ret;
	ret = average_event_count(&exist->rate_con, &exist->rate_cum, 
		&exist->rate_average, (int)latest->rates, &exist->rate_t, 5);
	if(ret == 1){
		//printf("WIPS_EID_BITRATE_CHANGED\n");
		report_wips_event(exist, WIPS_EID_BITRATE_CHANGED);
	}
}

void check_braodcast_storm(struct w_node * latest,struct w_node * exist)
{
	static int t, c;
	if(event_count(&c,80,&t,2 )){
		//printf("WIPS_EID_BRAODCAST_STORM\n");
		report_wips_event(exist, WIPS_EID_BRAODCAST_STORM);
	}
}

void check_signal(struct w_node * latest,struct w_node * exist)
{
	return;
	if(latest->signal < -96){
			//printf("WIPS_EID_SIGNAL_TOOLOW\n");
		report_wips_event(exist, WIPS_EID_SIGNAL_TOOLOW);
	}
}
int suppression_flags =0;
void check_freq_interference(struct w_node *sta_val)
{
	static int interval = 0;
	static int count = 0;
	static int flags = 0;

	w_tmp->rates = sta_val->rates;
	w_tmp->noise =	sta_val->noise;
	w_tmp->signal = sta_val->signal;
	w_tmp->channel = sta_val->channel;
	if(event_count(&count, 250, &interval, 5 )){
		if(flags != 1){
			flags = 1;
			w_tmp->node_type = 0x02;
			memset(w_tmp->alert, 0, ALERT_LEN * sizeof(__u32));
			//printf("WIPS_EID_INTERFERENCE\n");
			if(!suppression_flags)
				report_wips_event(w_tmp, WIPS_EID_INTERFERENCE);
		}
	}
	else if(flags == 1){
		flags = 0;
		w_tmp->node_type = 0x02;
		memset(w_tmp->alert, 0, ALERT_LEN * sizeof(__u32));
		report_wips_event(w_tmp, WIPS_EID_INTERFERENCE_2OK);
	}
}

void check_freq_suppression(struct w_node *sta_val)
{
	static int interval = 0;
	static int count = 0;

	w_tmp->rates = sta_val->rates;
	w_tmp->noise =	sta_val->noise;
	w_tmp->signal = sta_val->signal;
	w_tmp->channel = sta_val->channel;
	if(event_count(&count, 750, &interval, 5)){
		if(suppression_flags != 1){
			suppression_flags = 1;
			w_tmp->node_type = 0x02;
			memset(w_tmp->alert, 0, ALERT_LEN * sizeof(__u32));
			report_wips_event(w_tmp, WIPS_EID_SUPPRESSION);
		}
	}
	else if(suppression_flags == 1){
		suppression_flags = 0;
		w_tmp->node_type = 0x02;
		memset(w_tmp->alert, 0, ALERT_LEN * sizeof(__u32));
		report_wips_event(w_tmp, WIPS_EID_SUPPRESSION_2OK);
	}
}

void check_freq_err(struct w_node *sta_val)
{
#define CHANNEL_MAX_CE CHANNEL_MAX_5G
	static int interval[CHANNEL_MAX_CE] = {0}; 
	static int count[CHANNEL_MAX_CE] = {0}; 
	static int flags[CHANNEL_MAX_CE] = {0};
	int ch = sta_val->channel;

	w_tmp->rates = sta_val->rates;
	w_tmp->noise =	sta_val->noise;
	w_tmp->signal = sta_val->signal;
	w_tmp->channel = sta_val->channel;
	if(event_count(&count[ch], 250, &interval[ch], 5)){
		if(flags[ch] != 1){
			flags[ch] = 1;
			w_tmp->node_type = 0x02;
			memset(w_tmp->alert, 0, ALERT_LEN * sizeof(__u32));
			report_wips_event(w_tmp, WIPS_EID_FREQ_HARDWARE_ERR);
		}
	}
	else if(flags[ch] == 1){
		flags[ch] = 0;
		memset(w_tmp->alert, 0, ALERT_LEN * sizeof(__u32));
		report_wips_event(w_tmp, WIPS_EID_FREQ_HARDWARE_ERR2OK);
	}

#undef CHANNEL_MAX_CE
}

void print_event_info(int event_number, struct w_node *node)
{
#ifdef DEBUG_WIPSD	
    char str[128] = {0};
    int len = 0;
    
	len = snprintf(str, sizeof(str), MACSTR"--", MAC2STR(node->mac));

	switch(event_number){
		case WIPS_EID_ALL :
			strcat(str, "WIPS_EID_ALL\n");
			break;
		case WIPS_EID_ERR_CFG_GRP :
			strcat(str, "WIPS_EID_ERR_CFG_GRP\n");
			break;
		case WIPS_EID_NO_CRYPT_AP :
			strcat(str, "WIPS_EID_NO_CRYPT_AP\n");
			break;
		case WIPS_EID_CRYPT_WEP_AP :
			strcat(str, "WIPS_EID_CRYPT_WEP_AP\n");
			break;
		case WIPS_EID_WPS_AP :
			strcat(str, "WIPS_EID_WPS_AP\n");
			break;
		case WIPS_EID_WDS_AP :
			strcat(str, "WIPS_EID_WDS_AP\n");
			break;
		case WIPS_EID_WDS_STA :
			strcat(str, "WIPS_EID_WDS_STA\n");
			break;
		case WIPS_EID_AD_HOC :
			strcat(str, "WIPS_EID_AD_HOC\n");
			break;
		case WIPS_EID_AD_PKG :
			strcat(str, "WIPS_EID_AD_PKG\n");
			break;
		case WIPS_EID_UNAUTH_AP :
			strcat(str, "WIPS_EID_UNAUTH_AP\n");
			break;
//		case WIPS_EID_INVALID_FREQ_AP :
//			WIPSD_DEBUG("WIPS_EID_INVALID_FREQ_AP\n");
//			break;
		case WIPS_EID_STA_PROXY_AP :
			strcat(str, "WIPS_EID_STA_PROXY_AP\n");
			break;
//		case WIPS_EID_UNAUTH_MAC_FACT :
//			WIPSD_DEBUG("WIPS_EID_UNAUTH_MAC_FACT\n");
//			break;
		case WIPS_EID_PROBE_GRP :
			strcat(str, "WIPS_EID_PROBE_GRP\n");
			break;
		case WIPS_EID_FISHING_AP :
			strcat(str, "WIPS_EID_FISHING_AP\n");
			break;
		case WIPS_EID_HOTSPOTTER_AP :
			strcat(str, "WIPS_EID_HOTSPOTTER_AP\n");
			break;
		case WIPS_EID_AIRBASE_NG_FAKE_AP :
			strcat(str, "WIPS_EID_AIRBASE_NG_FAKE_AP\n");
			break;
		case WIPS_EID_MDK3_BEACON_FLOOD_AP :
			strcat(str, "WIPS_EID_MDK3_BEACON_FLOOD_AP\n");
			break;
		case WIPS_EID_DOS_GRP :
			strcat(str, "WIPS_EID_DOS_GRP\n");
			break;
		case WIPS_EID_DEAUTH_STA :
			strcat(str, "WIPS_EID_DEAUTH_STA\n");
			break;
		case WIPS_EID_MDK3_DEAUTH_STA :
			strcat(str, "WIPS_EID_MDK3_DEAUTH_STA\n");
			break;
		case WIPS_EID_AIREPLAY_NG_DEAUTH_STA :
			strcat(str, "WIPS_EID_AIREPLAY_NG_DEAUTH_STA\n");
			break;
		case WIPS_EID_DEASSO_STA :
			strcat(str, "WIPS_EID_DEASSO_STA\n");
			break;
		case WIPS_EID_MDK3_DEASSO_STA :
			strcat(str, "WIPS_EID_MDK3_DEASSO_STA\n");
			break;
		case WIPS_EID_AUTH_FLOOD_STA :
			strcat(str, "WIPS_EID_AUTH_FLOOD_STA\n");
			break;
		case WIPS_EID_ASSO_FLOOD_STA :
			strcat(str, "WIPS_EID_ASSO_FLOOD_STA\n");
			break;
		case WIPS_EID_PROBE_FLOOD_STA :
			strcat(str, "WIPS_EID_PROBE_FLOOD_STA\n");
			break;
		case WIPS_EID_ASSO_FLOOD_ACK_STA :
			strcat(str, "WIPS_EID_ASSO_FLOOD_ACK_STA\n");
			break;
		case WIPS_EID_ASSO_FLOOD_RTS_STA :
			strcat(str, "WIPS_EID_ASSO_FLOOD_RTS_STA\n");
			break;
		case WIPS_EID_ASSO_FLOOD_CTS_STA :
			strcat(str, "WIPS_EID_ASSO_FLOOD_CTS_STA\n");
			break;
		case WIPS_EID_DURATION_ATTACK :
			strcat(str, "WIPS_EID_DURATION_ATTACK\n");
			break;
		case WIPS_EID_CRACK_GRP :
			strcat(str, "WIPS_EID_CRACK_GRP\n");
			break;
		case WIPS_EID_VIOLENT_CRACK_STA :
			strcat(str, "WIPS_EID_VIOLENT_CRACK_STA\n");
			break;
		case WIPS_EID_AIREPLAY_NG_FRAMG_STA :
			strcat(str, "WIPS_EID_AIREPLAY_NG_FRAMG_STA\n");
			break;
		case WIPS_EID_AIREPLAY_NG_CHOP_STA :
			strcat(str, "WIPS_EID_AIREPLAY_NG_CHOP_STA\n");
			break;
		case WIPS_EID_AIREPLAY_NG_ARP_STA :
			strcat(str, "WIPS_EID_AIREPLAY_NG_ARP_STA\n");
			break;
		case WIPS_EID_WESSID_NG_STA :
			strcat(str, "WIPS_EID_WESSID_NG_STA\n");
			break;
		case WIPS_EID_INFO_GRP :
			strcat(str, "WIPS_EID_INFO_GRP\n");
			break;
		case WIPS_EID_ASSO_DENIED_STA :
			strcat(str, "WIPS_EID_ASSO_DENIED_STA\n");
			break;
		case WIPS_EID_NEW_DEVICE_AP :
			strcat(str, "WIPS_EID_NEW_DEVICE_AP\n");
			break;
		case WIPS_EID_NEW_DEVICE_STA :
			strcat(str, "WIPS_EID_NEW_DEVICE_STA\n");
			break;
		case WIPS_EID_DEVICE_DOWN_AP :
			strcat(str, "WIPS_EID_DEVICE_DOWN_AP\n");
			break;
		case WIPS_EID_DEVICE_DOWN_STA :
			strcat(str, "WIPS_EID_DEVICE_DOWN_STA\n");
			break;
		case WIPS_EID_STA_OFF_NETWORK :
			strcat(str, "WIPS_EID_STA_OFF_NETWORK\n");
			break;
		case WIPS_EID_STA_ON_NETWORK :
			strcat(str, "WIPS_EID_STA_ON_NETWORK\n");
			break;
		case WIPS_EID_FREQ_HARDWARE_ERR :
			strcat(str, "WIPS_EID_FREQ_HARDWARE_ERR\n");
			break;
		case WIPS_EID_FREQ_HARDWARE_ERR2OK :
			strcat(str, "WIPS_EID_FREQ_HARDWARE_ERR2OK\n");
			break;
		case WIPS_EID_FREQ_OVERLAPPING :
			strcat(str, "WIPS_EID_FREQ_OVERLAPPING\n");
			break;
		case WIPS_EID_TOOMANY_AP :
			strcat(str, "WIPS_EID_TOOMANY_AP\n");
			break;
		case WIPS_EID_TOOMANY_AP_INACHANNEL :
			strcat(str, "WIPS_EID_TOOMANY_AP_INACHANNEL\n");
			break;
//		case WIPS_EID_SNR_TOOLOW :
//			strcat(str, "WIPS_EID_SNR_TOOLOW\n");
//			break;
		case WIPS_EID_INTERFERENCE :
			strcat(str, "WIPS_EID_INTERFERENCE\n");
			break;
		case WIPS_EID_INTERFERENCE_2OK :
			strcat(str, "WIPS_EID_INTERFERENCE_2OK\n");
			break;
		case WIPS_EID_SUPPRESSION :
			strcat(str, "WIPS_EID_SUPPRESSION\n");
			break;
		case WIPS_EID_SUPPRESSION_2OK :
			strcat(str, "WIPS_EID_SUPPRESSION_2OK\n");
			break;
		case WIPS_EID_SIGNAL_TOOLOW :
			strcat(str, "WIPS_EID_SIGNAL_TOOLOW\n");
			break;
		case WIPS_EID_BRAODCAST_STORM :
			strcat(str, "WIPS_EID_BRAODCAST_STORM\n");
			break;
		case WIPS_EID_BITRATE_CHANGED :
			strcat(str, "WIPS_EID_BITRATE_CHANGED\n");
			break;
		case WIPS_EID_NOASSO_DATA :
			strcat(str, "WIPS_EID_NOASSO_DATA\n");
			break;
		case WIPS_EID_AP_SMALL_FRAG_PKG :
			strcat(str, "WIPS_EID_AP_SMALL_FRAG_PKG\n");
			break;
		case WIPS_EID_STA_SMALL_FRAG_PKG :
			strcat(str, "WIPS_EID_STA_SMALL_FRAG_PKG\n");
			break;
		case WIPS_EID_TOOMANY_BEACON :
			strcat(str, "WIPS_EID_TOOMANY_BEACON\n");
			break;
		case WIPS_EID_SEND2_ITSELF :
			strcat(str, "WIPS_EID_SEND2_ITSELF\n");
			break;
		case WIPS_EID_BRAODCAST_SMAC :
			strcat(str, "WIPS_EID_BRAODCAST_SMAC\n");
			break;
		case WIPS_EID_GROUP_SMAC :
			strcat(str, "WIPS_EID_GROUP_SMAC\n");
			break;
		case WIPS_EID_11N_DEVICE :
			strcat(str, "WIPS_EID_11N_DEVICE\n");
			break;
		case WIPS_EID_NO_QOS :
			strcat(str, "WIPS_EID_NO_QOS\n");
			break;
		case WIPS_EID_AP_REBOOTED :
			len += snprintf(str + len, sizeof(str) - len, "WIPS_EID_AP_REBOOTED  exist->timestamp[%lu]\n",
				node->timestamp);
			break;
		case WIPS_EID_AP_SIGNAL_TOOLOW :
			strcat(str, "WIPS_EID_AP_SIGNAL_TOOLOW\n");
			break;
		case WIPS_EID_AP_SIGNAL_TOOHIGH :
			strcat(str, "WIPS_EID_AP_SIGNAL_TOOHIGH\n");
			break;
		case WIPS_EID_CLOSE_PSPE :
			strcat(str, "WIPS_EID_CLOSE_PSPE\n");
			break;
		case WIPS_EID_RATESWITCH_TOOFAST :
			strcat(str, "WIPS_EID_RATESWITCH_TOOFAST\n");
			break;
		case WIPS_EID_AP_SUPPORT40MHZ :
			strcat(str, "WIPS_EID_AP_SUPPORT40MHZ\n");
			break;
		case WIPS_EID_STA_SIGNAL_TOOLOW :
			strcat(str, "WIPS_EID_STA_SIGNAL_TOOLOW\n");
			break;
		case WIPS_EID_STA_SIGNAL_TOOHIGH :
			strcat(str, "WIPS_EID_STA_SIGNAL_TOOHIGH\n");
			break;
		case WIPS_EID_AP_BRAODCAST_SSID :
			strcat(str, "WIPS_EID_AP_BRAODCAST_SSID\n");
			break;
		case WIPS_EID_REASSO_REFUSED :
			strcat(str, "WIPS_EID_REASSO_REFUSED\n");
			break;
		case WIPS_EID_WPA_REFUSED :
			strcat(str, "WIPS_EID_WPA_REFUSED\n");
			break;
		case WIPS_EID_AP_BG_MODE :
			strcat(str, "WIPS_EID_AP_BG_MODE\n");
			break;
		case WIPS_EID_AP_DEFAULTSSID :
			strcat(str, "WIPS_EID_AP_DEFAULTSSID\n");
			break;
		case WIPS_EID_STA_LISTENINTERVAL_TOOBIG :
			strcat(str, "WIPS_EID_STA_LISTENINTERVAL_TOOBIG\n");
			break;
		case WIPS_EID_STA_TOOMANY_RETRY :
			strcat(str, "WIPS_EID_STA_TOOMANY_RETRY\n");
			break;
		case WIPS_EID_AP_TOOMANY_RETRY :
			strcat(str, "WIPS_EID_AP_TOOMANY_RETRY\n");
			break;
		case WIPS_EID_AUTH_REFUSED :
			strcat(str, "WIPS_EID_AUTH_REFUSED\n");
			break;
		case WIPS_EID_AP_TOOMANY_QBSSSTA :
			strcat(str, "WIPS_EID_AP_TOOMANY_QBSSSTA\n");
			break;
		case WIPS_EID_AP_ESSID_DIFF :
			strcat(str, "WIPS_EID_AP_ESSID_DIFF\n");
			break;
		case WIPS_EID_PROBE_REFUSED :
			strcat(str, "WIPS_EID_PROBE_REFUSED\n");
			break;
		case WIPS_EID_PROBE_NOAUTH :
			strcat(str, "WIPS_EID_PROBE_NOAUTH\n");
			break;
		case WIPS_EID_ADHOC_SSID_AP_SSID_SAME :
			strcat(str, "WIPS_EID_ADHOC_SSID_AP_SSID_SAME\n");
			break;
		case WIPS_EID_UNAUTH_STA :
			strcat(str, "WIPS_EID_UNAUTH_STA\n");
			break;
		case WIPS_EID_AUTHSTA_UNAUTHAP :
			strcat(str, "WIPS_EID_AUTHSTA_UNAUTHAP\n");
			break;
		case WIPS_EID_AUTHSTA_EXTAP :
			strcat(str, "WIPS_EID_AUTHSTA_EXTAP\n");
			break;
		case WIPS_EID_UNAUTHSTA_INTERAP :
			strcat(str, "WIPS_EID_UNAUTHSTA_INTERAP\n");
			break;
		case WIPS_EID_UNAUTHSTA_PROBE_TOOMANY :
			strcat(str, "WIPS_EID_UNAUTHSTA_PROBE_TOOMANY\n");
			break;
//		case WIPS_EID_AP_FORBIDRATE :
//			strcat(str, "WIPS_EID_AP_FORBIDRATE\n");
//			break;
//		case WIPS_EID_STA_FORBIDRATE :
//			strcat(str, "WIPS_EID_STA_FORBIDRATE\n");
			break;
		case WIPS_EID_FORBID_CHANNEL :
			strcat(str, "WIPS_EID_FORBID_CHANNEL\n");
			break;
		case WIPS_EID_ACTION_GRP :
			strcat(str, "WIPS_EID_ACTION_GRP\n");
			break;
		case WIPS_EID_STA_BLOCK_START :
			strcat(str, "WIPS_EID_STA_BLOCK_START\n");
			break;
		case WIPS_EID_AP_BLOCK_START :
			strcat(str, "WIPS_EID_AP_BLOCK_START\n");
			break;
		case WIPS_EID_STA_BLOCK_STOP :
			strcat(str, "WIPS_EID_STA_BLOCK_STOP\n");
			break;
		case WIPS_EID_AP_BLOCK_STOP :
			strcat(str, "WIPS_EID_AP_BLOCK_STOP\n");
			break;
		default :
            strcat(str, "unknown\n");
			break;
	}
	WIPSD_DEBUG("%s", str);
#endif
}

int working_time_check(void)
{
	struct tm * local = NULL;
	
	return 0;
	local = localtime((const time_t * )&fresh_time);

	if(local->tm_wday == 0 || local->tm_wday == 6)
		return 1;

	if(local->tm_hour < 8 || local->tm_hour > 18)
		return 1;

	return 0;
}

int init_essid_hash_table(void)
{
	if ((node_essid_hash_table = hash_new()) == NULL){
		WIPSD_DEBUG("node_essid_hash_table hash_new failed");
		return -1;
	}
	
	return 0;
}

int transform_time(__u32 * t_h, __u32 * t_m, char * str);
int add_internal_ssid2list(char * ssid);
int read_ap_essid(void* data, int n_columns, char** column_values, 
	char** column_names)
{
	nodeInfo_exec_hook_para *sql_para = (nodeInfo_exec_hook_para *)data;
	essidObject *node;
	int * i;
	int len;
	if(!sql_para)return -1;
	node = sql_para->node;
	i = sql_para->i;

	if((*i) < OBJECT_MAX_NUM){}else{return 0;}
	if(column_values[0]){
		strncpy( node[(*i)].name, column_values[0], SSID_BUFSIZE);
		node[(*i)].name[SSID_BUFSIZE-1] = '\0';
		if(column_values[1]){
			len = sizeof(node[(*i)].type);
			strncpy( node[(*i)].type, column_values[1], len);
			node[(*i)].type[len-1] = '\0';
			if(strncmp(column_values[1], "internalnet", 4) == 0){
				add_internal_ssid2list(node[(*i)].name);
			}
		}
		if(column_values[2]){
			len = sizeof(node[(*i)].auth);
			strncpy( node[(*i)].auth, column_values[2], len);
			node[(*i)].auth[len-1] = '\0';
		}
		if(column_values[3]){
			len = sizeof(node[(*i)].mode);
			strncpy( node[(*i)].mode, column_values[3], len);
			node[(*i)].mode[len-1] = '\0';
		}
		if(column_values[4]){
			len = sizeof(node[(*i)].wtm1);
			strncpy( node[(*i)].wtm1, column_values[4], len);
			node[(*i)].wtm1[len-1] = '\0';
			len = strlen(node[(*i)].wtm1);
			node[(*i)].wtm1[len-1] = ' ';
			if(transform_time(&node[(*i)].start_h, &node[(*i)].start_m, node[(*i)].wtm1)>0){
				node[(*i)].start = (node[(*i)].start_h << 8) + node[(*i)].start_m;
			}
			node[(*i)].wtm1[len-1] = '\0';
		}
		if(column_values[5]){
			len = sizeof(node[(*i)].wtm2);
			strncpy( node[(*i)].wtm2, column_values[5], len);
			node[(*i)].wtm2[len-1] = '\0';
			len = strlen(node[(*i)].wtm2);
			node[(*i)].wtm2[len-1] = ' ';
			if(transform_time(&node[(*i)].end_h, &node[(*i)].end_m, node[(*i)].wtm2)>0){
				node[(*i)].end = (node[(*i)].end_h << 8) + node[(*i)].end_m;
			}
			node[(*i)].wtm2[len-1] = '\0';
		}
		if(column_values[6]){//ip
			len = sizeof(node[(*i)].ip);
			strncpy( node[(*i)].ip, column_values[6], len);
			node[(*i)].ip[len-1] = '\0';
		}
		if(column_values[7]){//mac
			len = sizeof(node[(*i)].mac);
			strncpy( node[(*i)].mac, column_values[7], len);
			node[(*i)].mac[len-1] = '\0';		
		}
		if( hash_insert(node_essid_hash_table, (const char *)node[(*i)].name, 0, 
		(void *)&node[(*i)]) == NULL){
			(*i)++;
		}
	}

	return 0;
}

int check_object_essid(char * wnet,struct w_node * exist)
{
	essidObject *node = NULL;
	node = (essidObject * )hash_find(node_essid_hash_table, (const char *)wnet, 0);
	if(node){
		if(memcmp(node->name, exist->ssid, sizeof(node->name)) == 0/*
			&& (memcmp(node->auth, "ÈÎÒâ", 4) == 0
			|| memcmp(node->auth, exist->sec_type, sizeof(exist->sec_type)) == 0)*/){
			return 1;
		}
	}else{
//		printf("check_object_essid: find a NULL point from hashTable!\n");
	}

	return 0;
}

int check_unworktime_essid_from_wnet(char * wnet)
{
	struct tm * local = NULL;
	essidObject *node = NULL;
	
	node = (essidObject * )hash_find(node_essid_hash_table, (const char *)wnet, 0);
	if(node){
		if(	!(node->start == 0 && node->end == 0) ){
			__u32 local_time = 0;
			local = localtime((const time_t * )&fresh_time);
			local_time = (local->tm_hour << 8) + local->tm_min;
			if(!(local_time >= node->start && local_time <= node->end)){
				return 1;
			}
		}
	}
	
	return 0;
}

int check_internal_essid_from_wnet(char * wnet)
{
	essidObject *node = NULL;
	node = (essidObject * )hash_find(node_essid_hash_table, (const char *)wnet, 0);
	if(node){
		if(memcmp(node->type, "internalnet", 4) == 0){
			return 'I';
		}else if(memcmp(node->type, "roguenet", 4) == 0){
			return -2;
		}else{
			return 0;
		}
	}else{
		return 1;
	}
}

int check_unauth_essid(struct w_node * exist)
{
	essidObject *node = NULL;
	node = (essidObject * )hash_find(node_essid_hash_table, (const char *)exist->ssid, 0);
	if(node){
			return 0;
	}

	return 1;
}

void get_shift_window(char *sub_str, char *window)
{
    int len = 0;
    int i = 0;

    len = strlen(sub_str);
    
    for(i=0; i<len; i++){
        window[(int)sub_str[i]] = len - i;
    }
    return;
}

void to_lower_str(char *str)
{
    __u32 len = 0;
    __u32 i = 0;

    len = strlen(str);
    for(i=0; i<len; i++){
        if(str[i] >= 'A' && str[i] <= 'Z'){
            str[i] += 32;
        }
    }
    return;
}

int check_object_vendor(char * object,char * vendor)
{
    int str_position = 0;
    int object_len = 0;
    int vendor_len = 0;
    char auc_shift[MAX_CHAR_NUM] = {0};
    if(NULL == vendor || NULL == object){
        return -1;
    }

	to_lower_str(object);
	to_lower_str(vendor);
    vendor_len = strlen(vendor);
    object_len = strlen(object);

    if(vendor_len < object_len){
        return -1;
    }
    
    memset(auc_shift, object_len, MAX_CHAR_NUM);
    get_shift_window(object, auc_shift);
    
    while(vendor_len - object_len >= str_position){
        if(CMP_OK != strncmp(vendor + str_position, object, object_len)){
            str_position += auc_shift[(int)vendor[str_position + object_len]];
        }else{
            return str_position + 1;
        }
    }
    return -1;
}

#define WIPSD_CONFIG_FILE_PATH "/usr/local/etc/wipsd.conf"
struct hash_control *node_ctime_hash_table;

int init_ctime_hash_table(void)
{
	if ((node_ctime_hash_table = hash_new()) == NULL){
		WIPSD_DEBUG("node_ctime_hash_table hash_new failed");
		return -1;
	}
	
	return 0;
}

int transform_time(__u32 * t_h, __u32 * t_m, char * str)
{
	char *tmp =NULL;
	int len =0;
	
	tmp = strchr(str, ':');
	len = tmp - str;
	if(len > 0 && len < 3){
		*tmp = '\0';
		*t_h = atoi(str);
	}else{
		return -1;
	}

	str = tmp + 1;
	tmp = strchr(str, ' ');
	len = tmp - str;
	if(len > 0 && len < 3){
		*tmp = '\0';
		*t_m = atoi(str);
	}else{
		return -1;
	}

	return 1;
}

int get_object_ctime(void)
{
	int count=0;
	static ctimeObject node[OBJECT_MAX_NUM];
	FILE * ssid_f =0;
	char buf[1024];
	unsigned long alloc;
	
	if ((ssid_f = fopen(WIPSD_CONFIG_FILE_PATH,"r")) == NULL){
		WIPSD_DEBUG ("Error, could not open %s (%s)\n", WIPSD_CONFIG_FILE_PATH, strerror(errno));
		return -1;
	}
	
	alloc = node_ctime_hash_table->size;
	alloc = alloc * sizeof(struct hash_entry *);
	memset (node_ctime_hash_table->table, 0, alloc);
	memset (node, 0, OBJECT_MAX_NUM*sizeof (ctimeObject));

	while (count < OBJECT_MAX_NUM && fgets (buf, 1024, ssid_f) != NULL){
		if(strncmp(buf, "schedule add name ",18) == 0){
			int ll = 0;
			ll = strlen(buf);
			buf[ll-1] = ' ';
			char *tmp_bp =NULL;
			char *buff = &buf[18];
			int len =0;

			tmp_bp = strchr(buff, ' ');
			len = tmp_bp - buff;
			if(len > SSID_BUFSIZE) len = SSID_BUFSIZE;
			memcpy( node[count].name, buff, len);
			node[count].name[len]= '\0';

			buff = tmp_bp + 1;
			if(strncmp(buff, "type weekcyc week ",18) == 0){
				int i=0;
				buff += 18;
				tmp_bp = strchr(buff, ' ');
				len = tmp_bp - buff;
				for(;len > i; i++){
					if(buff[i] > '0' && buff[i] < '8'){
						buff[i] -= 0x30;
						node[count].week |= 1 << buff[i];
					}
				}
				buff = tmp_bp + 1;
				if(strncmp(buff, "start ",6) == 0){
					buff += 6;
					tmp_bp = strchr(buff, ' ');
					if(transform_time(&node[count].start_h, &node[count].start_m, buff)>0){}
				}
				buff = tmp_bp + 1;
				if(strncmp(buff, "end ",4) == 0){
					buff += 4;
					tmp_bp = strchr(buff, ' ');
					if(transform_time(&node[count].end_h, &node[count].end_m, buff)>0){}
				}
				buff = tmp_bp + 1;
				if(strncmp(buff, "except-start ",13) == 0){
					buff += 13;
					tmp_bp = strchr(buff, ' ');
					if(transform_time(&node[count].except_start_h, &node[count].except_start_m, buff)>0){}
				}
				buff = tmp_bp + 1;
				if(strncmp(buff, "except-end ",11) == 0){
					buff += 11;
					tmp_bp = strchr(buff, ' ');
					if(transform_time(&node[count].except_end_h, &node[count].except_end_m, buff)>0){}
				}
				node[count].start = (node[count].start_h << 8) + node[count].start_m;
				node[count].end = (node[count].end_h << 8) + node[count].end_m;
				node[count].except_start = (node[count].except_start_h << 8) + node[count].except_start_m;
				node[count].except_end = (node[count].except_end_h << 8) + node[count].except_end_m;
			}
			memset (buf, 0, 1024);
		}else{
			memset (buf, 0, 1024);
			continue;
		}
		if( hash_insert(node_ctime_hash_table, (const char *)node[count].name, 0, 
		(void *)&node[count]) == NULL){
			count++;
		}
	}
	fclose(ssid_f);
	return 0;
}

int check_object_ctime(char * ctime)
{
	struct tm * local = NULL;
	ctimeObject *node = NULL;
	
	node = (ctimeObject * )hash_find(node_ctime_hash_table, (const char *)ctime, 0);
	if(node){
		__u32 local_time = 0;
		local = localtime((const time_t * )&fresh_time);
		if(local->tm_wday == 0) local->tm_wday = 7;
		if(node->week & (1 << local->tm_wday )){
			local_time = (local->tm_hour << 8) + local->tm_min;
			if(local_time >= node->except_start && local_time <= node->except_end){
			}else{
				if(local_time >= node->start && local_time <= node->end){
					return 1;
				}
			}
		}

	}

	return 0;
}

#if 0
bwlist_node * ssid_bwlist_head = NULL;
int read_ssidbwlist_config(void* data, int n_columns, char** column_values, char** column_names)
{
	bwlist_node * node = NULL;
	int len =0;

	if(column_values[0]){
		len = strlen(column_values[0]);
		//strcpy( buf, column_values[0]);
	}

	return 0;
}

int check_bwlist_ssid(struct w_node * latest,struct w_node * exist, char * com_type)
{
	//
	if(strcmp(com_type,"update")==0){
		bwlist_node * tmp = ssid_bwlist_head;
		bwlist_node * next = NULL;
		sqlite3 *sql = NULL;
		int ret;

		while(tmp){
			next = ssid_bwlist_head->next;
			wipsd_free(tmp->data);
			wipsd_free(tmp);
			tmp =next ;
		}
		ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
		if(ret != SQLITE_OK){
			WIPSD_DEBUG("open sqlite wconfig.db error !");
			return -1;
		}

		ret = -sqlite3_exec(sql, "select * from aplist", read_ssidbwlist_config, NULL,NULL);

	    if(sql)
	    	wipsd_sqlite3_close(sql);

		return ret;
	}else if(strcmp(com_type,"chek")==0){

	}
}
#endif

int blocked_bssid_with_sta(struct w_node * exist)
{
	blocked_bssid * tmp = NULL;
	if(!exist) return -1;
	if(exist->node_type & 1) return -1;

	if(exist->blocked_ap){
		blocked_bssid * node = exist->blocked_ap;
		for(;;){
			if(memcmp( node->bssid, exist->bssid, 6) == 0){
				goto blocked;
			}
			if(node->next){
				node = node->next;
			}else{
				break;
			}
		}
		tmp = XMALLOC(MTYPE_WIPS_DEBUG_BLOCKED_BSSID,sizeof(blocked_bssid));
		if(tmp == NULL){
			return -1;
		}
		memcpy( tmp->bssid, exist->bssid, 6);
		tmp->next = NULL;
		node->next = tmp;
	}else{
		tmp = XMALLOC(MTYPE_WIPS_DEBUG_BLOCKED_BSSID,sizeof(blocked_bssid));
		if(tmp == NULL){
			WIPSD_DEBUG("malloc for blocked_bssid_with_sta err!\n");
			return -1;
		}
		memcpy( tmp->bssid, exist->bssid, 6);
		tmp->next = NULL;
		exist->blocked_ap = tmp;
	}

	return 0;

blocked:
	return 1;
}

void free_blocked_bssid(struct w_node * exist)
{
	blocked_bssid * free_node = NULL;
	blocked_bssid *  tmp= NULL;
	if(!exist) return;
	if(exist->node_type & 1) return;

	free_node = exist->blocked_ap;
	exist->blocked_ap = NULL;
	while(free_node){
		tmp = free_node->next;
		XFREE(MTYPE_WIPS_DEBUG_BLOCKED_BSSID,free_node);
		free_node = tmp;
	}

}

void check_wireless_object(struct w_node * latest,struct w_node * exist)
{
	if(latest->node_type & 0x01){
		int ssid_type =0;
		if((ssid_type = check_internal_essid_from_wnet(exist->ssid)) > 0){
			nodeInfo * tmp=NULL;
			tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, 
					(const char *)exist->mac, 6);
			if(tmp){
				int node_type = tmp->node_type & 0x180;
				if(node_type == 0){//ext
					exist->internal_node = FALSE;
					exist->ipv4[0] = '\0';
					strncpy( exist->name,tmp->name,sizeof(exist->name));

				}else if(node_type == 0x80){//in
					exist->internal_node = TRUE;
					if(tmp->ipv4[0] != '\0'){
						strncpy( exist->ipv4,tmp->ipv4,sizeof(exist->ipv4));
					}
					strncpy( exist->name,tmp->name,sizeof(exist->name));
				//	if(exist->ssid[0]!='\0')add_internal_ssid2list(exist->ssid);
				}else{//rogue
					exist->internal_node = FALSE;
					exist->ipv4[0] = '\0';
                    //clear_wips_event(exist, WIPS_EID_UNAUTH_AP);
					report_wips_event(exist, WIPS_EID_UNAUTH_AP);
					strncpy( exist->name,tmp->name,sizeof(exist->name));
				}
			}else{
				if(latest->internal_node == TRUE){
					exist->internal_node = TRUE;
//					if(exist->ipv4[0] == '\0')
						memcpy( exist->ipv4,latest->ipv4,sizeof(exist->ipv4));
		//			if(exist->ssid[0]!='\0')add_internal_ssid2list(exist->ssid);
				}else if(ssid_type == 'I'){
	//				exist->internal_node = TRUE;
	//				if(exist->ipv4[0] == '\0'){
	//					memset(exist->ipv4, 0, sizeof(exist->ipv4));
	//					memcpy( exist->ipv4,"    ",4);
	//				}
			//		if(exist->ssid[0]!='\0')add_internal_ssid2list(exist->ssid);
				}
			}
		}else{
			nodeInfo * tmp=NULL;
			tmp = (nodeInfo * )hash_find(nodeinfo_hash_table, 
					(const char *)exist->mac, 6);
			if(tmp){
				int node_type = tmp->node_type & 0x180;
				if(node_type == 0){//ext
					exist->internal_node = FALSE;
					exist->ipv4[0] = '\0';
				}else if(node_type == 0x80){//in
					exist->internal_node = TRUE;
					if(tmp->ipv4[0] != '\0'){
						strncpy( exist->ipv4,tmp->ipv4,sizeof(exist->ipv4));
					}
		//			if(exist->ssid[0]!='\0')add_internal_ssid2list(exist->ssid);
				}else{//rogue
					exist->internal_node = FALSE;
					exist->ipv4[0] = '\0';
		//			report_wips_event(exist, WIPS_EID_UNAUTH_AP);
				}
			}else if(latest->internal_node == TRUE){
				exist->internal_node = TRUE;
				memcpy( exist->ipv4,latest->ipv4,sizeof(exist->ipv4));
//				if(exist->ssid[0]!='\0')add_internal_ssid2list(exist->ssid);
			}
		}

	}
}

