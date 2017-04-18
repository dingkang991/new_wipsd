#include <zebra.h>
#include <sys/un.h>
#include <string.h>
#include "zthread_support.h"
#include "if_support.h"
#include "fs_support.h"
#include "if.h"
#include "getopt.h"
#include "memory.h"
#include "message.h"
#include "vty.h"
#include "zclient.h"
#include "vtysh/vtysh.h"
#include "wipsd_vty.h"
#include "sqlite3.h"
#include "sys/hls_config.h"
#include "sys/hls_config_util.h"
#include "message.h"
#include "wipsd_wnode.h"
#include "wipsd_interface.h"
#include "wipsd.h"
#include "event_mem_log.h"
#include "../../../kernel/include/linux/netfilter_ipv4/fw_objects.h"

#define P(x) ((x != NULL)?(x):"")
#define min(x,y) ((x) < (y) ? x : y)

#define NMACQUAD_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
int send_len = 0;
int wnet_line = 0;
int ap_line = 0;
int sta_line = 0;
int wpolicy_line = 0;
int wips_event_line = 0;
int have_wpolicy = 0;
int wips_log_num = 0;
int wnet_cfg_num = 0;

extern int log_mode;/*0:all,1:local syslog,2:remote syslog*/
extern unsigned int syslog_ip;
extern unsigned short syslog_port;
extern w_node_list * beacon_list_p;
extern w_node_list * beacon_list_tail;
extern w_node_list * sta_list_p;
extern w_node_list * sta_list_tail;
extern struct wipsd_interface_hdr *wipsd_itf_list;
extern pthread_mutex_t event_memlog_mutex;
extern struct memlog event_memlog;
extern int signal_threshold;
extern int wireless_node_age;
extern int wireless_node_dead_time;
extern int show_all_infor;
extern int packet_syslog_out;
extern int wips_event_syslog_out;




struct wipsd_wnet_trans *wnet_trans = NULL;
struct oam_data_st *wnet_data = NULL;
struct wipsd_ap_trans *ap_trans = NULL;
struct oam_data_st *ap_data = NULL;
struct wipsd_sta_trans *sta_trans = NULL;
struct oam_data_st *sta_data = NULL;
struct wipsd_policy_trans *wpolicy_trans = NULL;
struct oam_data_st *wpolicy_data = NULL;
struct wipsd_wips_event_trans *wips_event_trans = NULL;
struct oam_data_st *wips_event_data = NULL;
extern int wpolicy_update_tag;
extern int sqlite3_get_row( sqlite3 *sql, const char *query, 
	char ***dbResult, int *row, int *col, char **errmsg);

char *wipsd_convert_star2space(char *str)
{
	char *p = str;
	
	if(p == NULL)
		return NULL;

	while(*p != '\0') {
		if(*p == '*')
			*p = ' ';
		p++;
	}

	return str;
}

void wipsd_get_str_from_macaddr( unsigned char * mac , char * str )
{
	sprintf( str, "%02x:%02x:%02x:%02x:%02x:%02x", 
		mac[ 0 ], mac[ 1 ], mac[ 2 ], mac[ 3 ], mac[ 4 ], mac[ 5 ] );
	return ;
}

void wipsd_get_string_from_macaddr( unsigned char * mac , char * str )
{
	sprintf( str, "%02x:%02x:%02x:%02x:%02x:%02x", 
		mac[ 0 ], mac[ 1 ], mac[ 2 ], mac[ 3 ], mac[ 4 ], mac[ 5 ] );
	return ;
}
char *convert_ap_mode(short rg, short rn)
{

	if(rg == 0 && rn == 0)
		return "802.11b";
	else if(rg == 0 && rn == 1)
		return "802.11n";
	else if(rg == 1 && rn == 0)
		return "802.11bg";
	else if(rg == 1 && rn == 1)
		return "802.11bgn";
	else
		return "Unknown";

	return NULL;
}

char *wipsd_phy_mode(enum ieee80211_phymode phy_mode)
{
    switch (phy_mode)
    {
        case IEEE80211_MODE_11A:
            return "802.11a";
        case IEEE80211_MODE_11B:
            return "802.11b";
        case IEEE80211_MODE_11G:
            return "802.11g";
        case IEEE80211_MODE_11NA:
            return "802.11na";
        case IEEE80211_MODE_11NG:
            return "802.11ng";
        case IEEE80211_MODE_11AC:
            return "802.11ac";
        default:
            break;
    }

	return "Unknown";
}

/*
如果合法的MAC返回0 ，不合法返回-1
合法的MAC为xx:xx:xx:xx:xx:xx
src_mac经过处理后去掉冒号保存在addr中
*/
int wipsd_mac_colon_to_string (unsigned char *addr, char *src_mac)
{
	int num = 6;
	int total;
	unsigned char *ptr = NULL;
	unsigned char mac[20];

	memset (mac, 0, 20);
	strncpy ((char *)mac, src_mac, 20);
	mac[strlen ((char *)mac)] = '\0';
	ptr = (unsigned char *) strrchr ((const char *)mac, ':');
	while (ptr)
	{
		*ptr = '\0';
		total = 0;
		
		if (!isdigit (*(ptr + 1)) && !isdigit (*(ptr + 2))
			&& !isalpha (*(ptr + 1)) && !isalpha (*(ptr + 2))){
			return -1;
		}

		if ((*(ptr + 3) != '\0') || (*(ptr + 2) == '\0')){
			return -1;
		}
		
		if (isalpha (*(ptr + 1))){
			if (tolower (*(ptr + 1)) > 'f'){
	    			return -1;
			}
			
			total += (tolower (*(ptr + 1)) - 87) * 16;
		}else{
			total += (*(ptr + 1) - 48) * 16;
		}
		
		if (isalpha (*(ptr + 2))){
			if (tolower (*(ptr + 2)) > 'f'){
				return -1;
			}
			
			total += tolower (*(ptr + 2)) - 87;
		}else{
			total += *(ptr + 2) - 48;
		}

		num--;
		*(addr + num) = total;
		ptr = (unsigned char *) strrchr ((char *)mac, ':');
	}

	if (!isdigit (*(mac + 1)) && !isdigit (*(mac)) && !isalpha (*(mac + 1))
	  && !isalpha (*(mac))){
		return -1;
	}
	
	if ((*(mac + 2) != '\0') && (*(mac + 1) == '\0')){
		return -1;
	}
	
	total = 0;
	if (isalpha (*(mac))){
		if (tolower (*(mac)) > 'f'){	
			return -1;
		}
		
	  	total += (tolower (*(mac)) - 87) * 16;
	}else{
		total += (*(mac) - 48) * 16;
	}
	
	if (isalpha (*(mac + 1))){
		if (tolower (*(mac + 1)) > 'f'){	
			return -1;
		}

		total += tolower (*(mac + 1)) - 87;
	}else{
		total += *(mac + 1) - 48;
	}
		
	*(addr) = total;
	if (num == 1){
		return 0;
	}else{
		return -1;
	}
}

int wipsd_wnet_add(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;  
	char *errmsg = NULL;
	char query[1024];
	char arg_mac_value[18];

	char *arg_name_value = (char *)&trans->name;
	char *arg_type_value = (char *)&trans->type;
	char *arg_auth_value = (char *)&trans->auth;
	char *arg_mode_value = (char *)&trans->mode;
	char *arg_wtm1_value = (char *)&trans->start_time;
	char *arg_wtm2_value = (char *)&trans->end_time;
	char *arg_gw_value = (char *)&trans->gw;
	 
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from wnet where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
       if(ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_SQL_PROCESS;
       }
	   
	if(row > 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_WNET_EXIST;	
	}

	memset((void *)arg_mac_value, 0, sizeof(arg_mac_value));
	if(strncmp((char *)trans->mac,"any",3)){
		wipsd_get_str_from_macaddr(trans->mac , arg_mac_value);
	}else{
		memcpy((void *)arg_mac_value, trans->mac, sizeof(arg_mac_value));
	}
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"insert into wnet (\"name\", \"type\", \"auth\", \"mode\", \"ip\", \"mac\", \"wtm1\", \"wtm2\")"
				" values(\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\")",
				wipsd_convert_star2space(arg_name_value), arg_type_value, 
				arg_auth_value, arg_mode_value, arg_gw_value, arg_mac_value, 
				arg_wtm1_value, arg_wtm2_value);
	ret = sqlite3_exec(sql, query, NULL, NULL, &errmsg);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_ADD_FAIL;
	}
	
	if(sql){
		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wnet_encrypt_config(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	char *arg_name_value = (char *)&trans->name;
	char *arg_auth_value = (char *)&trans->auth;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), "update wnet set auth=\"%s\" where name=\"%s\"",
		arg_auth_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret != SQLITE_OK){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}
	
	if(sql){
    		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}


int wipsd_wnet_mode_config(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	char *arg_name_value = (char *)&trans->name;
	char *arg_mode_value = (char *)&trans->mode;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), "update wnet set mode=\"%s\" where name=\"%s\"",
		arg_mode_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}

	if(sql){
    		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wnet_time_range_config(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	char *arg_name_value = (char *)&trans->name;
	char *arg_start_time_value = (char *)&trans->start_time;
	char *arg_end_time_value = (char *)&trans->end_time;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), "update wnet set wtm1=\"%s\" where name=\"%s\"",
		arg_start_time_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret){	
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), "update wnet set wtm2=\"%s\" where name=\"%s\"",
		arg_end_time_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}

	if(sql){	
    		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wnet_gateway_config(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	char *errmsg = NULL;
	
	char *arg_name_value = (char *)&trans->name;
	char *arg_gw_value = (char *)&trans->gw;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){	
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), "update wnet set ip=\"%s\" where name=\"%s\"",
			arg_gw_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, &errmsg);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}

	if(sql){
    		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wnet_mac_config(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	char arg_mac_value[18];
	
	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	memset((void *)arg_mac_value, 0, sizeof(arg_mac_value));
	wipsd_get_str_from_macaddr( trans->mac , arg_mac_value );
	snprintf(query, sizeof(query), "update wnet set mac=\"%s\" where name=\"%s\"",
		arg_mac_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}

	if(sql){
    		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wnet_config(struct wipsd_wnet_trans *trans)
{

	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;  
	char *errmsg = NULL;
	char query[1024];

	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from wnet where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
       if(ret < 0 ||row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_WNET_UNEXIST;
       }	   

	if(sql){
		sqlite3_close(sql);
	}
		
	return 0;
}

int wipsd_wnet_delete(struct wipsd_wnet_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char query[1024];
	char **dbResult = NULL;
	char *errmsg  = NULL;

	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from wnet where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
       if(ret < 0 || row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_WNET_UNEXIST;
       }

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from wpolicy where wnet=\"%s\"",
		wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if (ret < 0 ||row > 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_WNET_USED;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"delete from wnet where name=\"%s\"", 
		wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if (ret < 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_DEL_FAIL;
	}
	
	if(sql){
		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wnet_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_IPC_OK;
	struct wipsd_wnet_st *wnet_st = (struct wipsd_wnet_st *)buf;
	struct wipsd_wnet_trans *trans = NULL;

	if(wnet_st == NULL){
		vsos_assert(0);
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &wnet_st->trans;
	switch(wnet_st->cmd){
		case WIPSD_WNET_ADD:
			ret = wipsd_wnet_add(trans);
			break;
		case WIPSD_WNET_CONFIG:
			ret = wipsd_wnet_config(trans);
			break;
		case WIPSD_WNET_ENCRYPT_CONFIG:
			ret = wipsd_wnet_encrypt_config(trans);
			break;
		case WIPSD_WNET_MODE_CONFIG:
			ret = wipsd_wnet_mode_config(trans);
			break;
		case WIPSD_WNET_TIME_RANGE_CONFIG:
			ret = wipsd_wnet_time_range_config(trans);
			break;
		case WIPSD_WNET_GATEWAY_CONFIG:
			ret = wipsd_wnet_gateway_config(trans);
			break;
		case WIPSD_WNET_MAC_CONFIG:
			ret = wipsd_wnet_mac_config(trans);
			break;
		case WIPSD_WNET_DEL:
			ret = wipsd_wnet_delete(trans);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	
	return ret;
}

int wipsd_wnet_dump_show
	(void *data, int n_columns, char** column_values, char** column_names)
{
	int fd = *((int *)data);
	char *outbuf = NULL;
	struct wipsd_wnet_trans *trans = NULL;

	outbuf = (char *)wnet_trans;
	trans = wnet_trans + wnet_line;
	if(send_len < sizeof(struct wipsd_wnet_trans)){
		wnet_data->datalen  = OAM_MAX_DATA_LEN - send_len;
		write(fd,  wnet_data, OAM_BUF_LEN);
		memset(outbuf, 0, OAM_MAX_DATA_LEN);
		wnet_data->datalen = 0;
		wnet_line = 0;
		trans = wnet_trans;
		send_len = OAM_MAX_DATA_LEN;
	}
	
	memset((void *)trans, 0, sizeof(struct wipsd_wnet_trans));
	strncpy((void *)trans->name, (void *)column_values[0], sizeof(trans->name) - 1);
	strncpy((void *)trans->type, (void *)column_values[1], sizeof(trans->type) - 1);
	strncpy((void *)trans->auth, (void *)column_values[2], sizeof(trans->auth) - 1);
	strncpy((void *)trans->mode, (void *)column_values[3], sizeof(trans->mode) - 1);
	strncpy((void *)trans->gw, (void *)column_values[4], sizeof(trans->gw) - 1);

    if (strncmp(column_values[5], "any", 3))
    {
    	wipsd_mac_colon_to_string((void *)trans->mac, (void *)column_values[5]);
    }
    else
        strlcpy((void *)trans->mac, (void *)column_values[5], sizeof(trans->mac));

	strncpy((void *)trans->start_time, (void *)column_values[6], sizeof(trans->start_time) - 1);
	strncpy((void *)trans->end_time, (void *)column_values[7], sizeof(trans->end_time) - 1);

	wnet_line++;
	send_len -= sizeof(struct wipsd_wnet_trans);
	
	return 0;
}

int wipsd_wnet_dump(char *buf, char *outbuf, int *len, int fd)
{
	int row = 0;
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg = NULL;
	char query[1024];
	
	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));
	struct wipsd_wnet_trans *trans = (struct wipsd_wnet_trans *)buf;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret){
		return WIPSD_ERR_OPEN_FILE;
	}
	 
	memset((void *)query, 0, sizeof(query));
	if(buf && (strlen((void *)trans->name) > 0)){
		snprintf(query,sizeof(query), "select * from wnet where name = \"%s\"",trans->name);
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_WNET_UNEXIST;
		}
		
	}else{
		snprintf(query,sizeof(query), "select * from wnet");
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_WNET_UNEXIST;
		}
	}

	wnet_data = (struct oam_data_st *)data;
	wnet_trans = (struct wipsd_wnet_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;
	ret = sqlite3_exec(sql, query, wipsd_wnet_dump_show, &fd, &errmsg);
	if(ret){
		sqlite3_close(sql);
		wnet_line = 0;
		wnet_trans = NULL;
		wnet_data =NULL;
		return WIPSD_ERR_SQL_PROCESS;
	}

	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN- sizeof(struct wipsd_wnet_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	wnet_line = 0;
	wnet_trans = NULL;
	wnet_data =NULL;
	if(sql){
		sqlite3_close(sql);
	}
	
	return ret;
}

int wipsd_ap_dump_show
	(void *data, int n_columns, char** column_values, char** column_names)
{
	int fd = *((int *)data);
	char *outbuf = NULL;
	struct wipsd_ap_trans *trans = NULL;

	outbuf = (char *)ap_trans;
	trans = ap_trans + ap_line;
	if(send_len < sizeof(struct wipsd_ap_trans)){
		ap_data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd,  ap_data, OAM_BUF_LEN);
		memset(outbuf, 0, OAM_MAX_DATA_LEN);
		ap_data->datalen = 0;
		ap_line = 0;
		trans = ap_trans;
		send_len = OAM_MAX_DATA_LEN;
	}

	memset((void *)trans, 0, sizeof(struct wipsd_ap_trans));
	strncpy((void *)trans->name, (void *)column_values[0], sizeof(trans->name) - 1);
	strncpy((void *)trans->type, (void *)column_values[1], sizeof(trans->type) - 1);
	strncpy((void *)trans->ip,(void *)column_values[2],sizeof(trans->ip) - 1);
    if (strncmp(column_values[3], "any", 3))
    {
    	wipsd_mac_colon_to_string((void *)trans->mmac, (void *)column_values[3]);
    }
    else
        strncpy((void *)trans->mmac, (void *)column_values[3], sizeof(trans->mmac) - 1);
        
    if (strncmp(column_values[4], "any", 3))
    {
    	wipsd_mac_colon_to_string((void *)trans->wmac, (void *)column_values[4]);
    }
    else
        strncpy((void *)trans->wmac, (void *)column_values[4], sizeof(trans->wmac) - 1);

	strncpy((void *)trans->vendor, (void *)column_values[5], sizeof(trans->vendor) - 1);

	ap_line++;
	send_len -= sizeof(struct wipsd_ap_trans);

	return 0;
}

int wipsd_ap_add(struct wipsd_ap_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int col = 0;
	int row1 = 0;
	int row2 = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;  
	char *errmsg = NULL;
	char query[1024];
	char arg_mmac_value[18];
	char arg_wmac_value[18];

	char *arg_name_value = (char *)&trans->name;
	char *arg_type_value = (char *)&trans->type;
	char *arg_ip_value =(char *)&trans->ip;
	char *arg_vendor_value =(char *)&trans->vendor;
	
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	memset((void *)arg_mmac_value, 0, sizeof(arg_mmac_value));
	if(strncmp((char *)trans->mmac,"any",3)){
		wipsd_get_str_from_macaddr(trans->mmac , arg_mmac_value);
	}else{
		memcpy((void *)arg_mmac_value,"any",3);
	}
    
	memset((void *)arg_wmac_value, 0, sizeof(arg_wmac_value));
	if(strncmp((char *)trans->wmac,"any",3)){
		wipsd_get_str_from_macaddr(trans->wmac , arg_wmac_value);
	}else{
		memcpy((void *)arg_wmac_value,"any",3);
	}
    
	snprintf(query, sizeof(query), "select * from aplist where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row1, &col, &errmsg);
	if(ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_SQL_PROCESS;
	}	

	if(row1 > 0) {
		if(sql) {
    			sqlite3_close(sql);
		}
		
		return WIPSD_ERR_AP_EXIST;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"select * from aplist where wmac=\"%s\"",arg_wmac_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row2, &col, &errmsg);		
	if(ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_SQL_PROCESS;
		
	}

	if(row2 > 0) {
		if(sql) {
    			sqlite3_close(sql);
		}
		
		return WIPSD_ERR_AP_RADIO_MAC_EXIST;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query,sizeof(query), 
		"insert into aplist (\"name\", \"type\", \"ip\",  \"mmac\", \"wmac\", \"vendor\")"
		"values(\"%s\", \"%s\", \"%s\", \"%s\",\"%s\", \"%s\")",
		wipsd_convert_star2space(arg_name_value), arg_type_value,
		arg_ip_value,arg_mmac_value,arg_wmac_value, 
		P(wipsd_convert_star2space(arg_vendor_value)));
	ret = sqlite3_exec(sql, query, NULL, NULL, &errmsg);
	if(ret != SQLITE_OK){
		return WIPSD_ERR_ADD_FAIL;
	}

	wpolicy_update_tag = 1;
	if(sql){
		sqlite3_close(sql);
	}
	
	return 0;
}

int wipsd_ap_delete(struct wipsd_ap_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg  = NULL;
	char query[1024];

	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), "select * from aplist where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if(ret < 0 || row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_AP_UNEXIST;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"select * from wpolicy where ap_mac=\"%s\"", arg_name_value);//ap_mac :ap name
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if (ret < 0 || row > 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_AP_USED;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"delete from aplist where name=\"%s\"", arg_name_value);
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if (ret < 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_DEL_FAIL;
	}
	
	if(sql){
		sqlite3_close(sql);
	}
	
	wpolicy_update_tag = 1;
	return 0;
}
	
int wipsd_ap_config(struct wipsd_ap_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;  
	char *errmsg = NULL;
	char query[1024];

	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from aplist where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
       if(ret < 0 ||row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_AP_UNEXIST;
       }	   

	if(sql){
		sqlite3_close(sql);
	}
		
	return 0;
}

int wipsd_ap_company_config(struct wipsd_ap_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	
	char *arg_name_value = (char *)&trans->name;
	char *arg_vendor_value = (char *)&trans->vendor;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), 
		"update aplist set vendor=\"%s\" where name=\"%s\"",
		arg_vendor_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}
	
	if(sql){
    		sqlite3_close(sql);
	}
	
	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_ap_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_IPC_OK;
	struct wipsd_ap_st *ap_st = (struct wipsd_ap_st *)buf;
	struct wipsd_ap_trans *trans = NULL;

	if(ap_st == NULL){
		vsos_assert(0);
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &ap_st->trans;
	switch(ap_st->cmd){
		case WIPSD_AP_ADD:
			ret = wipsd_ap_add(trans);
			break;
		case WIPSD_AP_DEL:
			ret = wipsd_ap_delete(trans);
			break;
		case WIPSD_AP_CONFIG:
			ret = wipsd_ap_config(trans);
			break;
		case WIPSD_AP_COMPANY_CONFIG:
			ret = wipsd_ap_company_config(trans);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	
	if(ret){
		*len = sizeof(ret);
	}
	
	return ret;
}

int wipsd_ap_dump(char *buf, char *outbuf, int *len, int fd)
{
	int row = 0;
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg = NULL;
	char query[1024];

	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));
	struct wipsd_ap_trans *trans = (struct wipsd_ap_trans *)buf;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	 
	memset((void *)query, 0, sizeof(query));
	if(buf && (strlen((void *)trans->name) > 0)){
		snprintf(query,sizeof(query), "select * from aplist where name = \"%s\"",trans->name);
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_AP_UNEXIST;
		}
		
	}else{
		snprintf(query,sizeof(query), "select * from aplist");
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_AP_UNEXIST;
		}
	}

	ap_data = (struct oam_data_st *)data;
	ap_trans = (struct wipsd_ap_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;
	ret = sqlite3_exec(sql, query, wipsd_ap_dump_show, &fd, &errmsg);
	if(ret){
		sqlite3_close(sql);
		ap_line = 0;
		ap_data = NULL;
		ap_trans = NULL;
		return WIPSD_ERR_SQL_PROCESS;
	}
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN - sizeof(struct wipsd_ap_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	ap_line = 0;
	ap_data = NULL;
	ap_trans = NULL;
	if(sql){
		sqlite3_close(sql);
	}
	
	return ret;
}

int wipsd_ap_learn_dump(char *buf, char *outbuf, int *len, int fd)
{
	int send_len = 0;
	w_node_list * tmp_node = NULL;
	struct wipsd_ap_info_trans *trans = NULL;
	struct wipsd_sta_ap_show *option;

	option = (struct wipsd_sta_ap_show *)buf;

	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));	

	trans = (struct wipsd_ap_info_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;

	if(beacon_list_p == NULL && beacon_list_tail == NULL){
		return WIPSD_OK;
	}
		
	for (tmp_node = beacon_list_p; tmp_node != NULL;){
		if(send_len < sizeof(struct wipsd_ap_info_trans)){
			data->datalen = OAM_MAX_DATA_LEN - send_len;
			write(fd, data, OAM_BUF_LEN);//(OAM_MAX_DATA_LEN)-send_len+sizeof(struct oam_data_st)
			memset(outbuf, 0, OAM_MAX_DATA_LEN);
			data->datalen = 0;
			trans = (struct wipsd_ap_info_trans *)outbuf;
			send_len = OAM_MAX_DATA_LEN;
		}
		if(show_all_infor || 0 != tmp_node->b_frame.ssid[0] || 0 != tmp_node->b_frame.sec_type[0])
		{

			memset((void *)trans, 0, sizeof(struct wipsd_ap_info_trans));
			strncpy((void*)trans->name, (void*)tmp_node->b_frame.name, OBJ_SHORT_NAME_MAX_LEN);
			strncpy((void*)trans->ssid, (void*)tmp_node->b_frame.ssid, SSID_BUFSIZE_D);
			strncpy((void*)trans->ip, (void*)tmp_node->b_frame.ipv4, OBJ_IP_MAX_LEN);	//ap type
			trans->band=tmp_node->b_frame.freq_band;
			trans->channel=tmp_node->b_frame.channel;
			trans->signal=tmp_node->b_frame.signal_average;
			trans->noise=tmp_node->b_frame.noise;
			trans->up_time=tmp_node->b_frame.up_time;
			trans->last_time=tmp_node->b_frame.last_time;
			trans->internal = tmp_node->b_frame.internal_node;
			strncpy((void*)trans->mode, (void*)wipsd_phy_mode(tmp_node->b_frame.phy_mode), OBJ_SHORT_NAME_MAX_LEN);
			strncpy((void*)trans->sec_type, (void*)tmp_node->b_frame.sec_type, OBJ_NAME_MAX_LEN);
			memcpy((void*)trans->mmac, (void*)tmp_node->b_frame.mac, ETH_ALEN);
			memcpy((void*)trans->wmac, (void*)tmp_node->b_frame.mac, ETH_ALEN);
			memcpy((void*)trans->mmac, (void*)tmp_node->b_frame.prober_mac, ETH_ALEN);
			strncpy((void*)trans->vendor, (void*)tmp_node->b_frame.vendor, OBJ_DATA_MAX_LEN);

			trans++;
			send_len -= sizeof(struct wipsd_ap_info_trans);
		}
		tmp_node= tmp_node->next;
	}
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN - sizeof(struct wipsd_ap_info_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	return WIPSD_OK;
}


int wipsd_sta_add(struct wipsd_sta_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row1 =0;
	int col =0;
	int row2=0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg = NULL;
	char query[1024];
	char arg_mac_value[18];
	
	char *arg_name_value = (char *)&trans->name;
	char *arg_mask_value = {"48"};
	char *arg_vendor_value = (char *)&trans->vendor;
	
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	memset((void *)arg_mac_value, 0, sizeof(arg_mac_value));
	wipsd_get_str_from_macaddr( trans->mac , arg_mac_value );
	snprintf(query,sizeof(query),
		"select * from stalist where name=\"%s\"",arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row1, &col, &errmsg);
	if(ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_SQL_PROCESS;
	}

	if(row1 > 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_STA_EXIST;
	}

	memset((void *)query, 0, sizeof(query));
	if(arg_mac_value) {
		snprintf(query, sizeof(query),
			"select * from stalist where mac=\"%s\"",arg_mac_value);
		ret = sqlite3_get_row( sql, query, &dbResult, &row2, &col, &errmsg);
		if(ret < 0){
			sqlite3_close(sql);
			return WIPSD_ERR_SQL_PROCESS;
		}
	}

	if(row2 > 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_STA_MAC_EXIST;
	}
		
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"insert into stalist (\"name\", \"mac\", \"mask\", \"vendor\")"
		"values(\"%s\", \"%s\", \"%s\", \"%s\")",
		wipsd_convert_star2space(arg_name_value), arg_mac_value, P(arg_mask_value),
		P(wipsd_convert_star2space(arg_vendor_value)));
	ret = sqlite3_exec(sql, query, NULL, NULL, &errmsg);
	if(ret != SQLITE_OK){
		return WIPSD_ERR_ADD_FAIL;	
	}
	
	if(sql){
		sqlite3_close(sql);
	}
	
	wpolicy_update_tag = 1;
	return 0;

}

int wipsd_sta_delete(struct wipsd_sta_trans *trans)
{
	int row = 0;
	int col = 0;
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg  = NULL;
	char query[1024];

	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query,sizeof(query),
		"select * from stalist where name=\"%s\"",arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if(ret < 0 || row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_STA_UNEXIST;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), 
		"select * from wpolicy where sta_mac=\"%s\"",arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if (ret < 0 || row > 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_STA_USED;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"delete from stalist where name=\"%s\"", arg_name_value);
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if (ret < 0) {
		sqlite3_close(sql);
		return WIPSD_ERR_DEL_FAIL;
	}
	
	if(sql){
		sqlite3_close(sql);
	}
    
	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_sta_config(struct wipsd_sta_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;  
	char *errmsg = NULL;
	char query[1024];

	char *arg_name_value = (char *)&trans->name;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from stalist where name=\"%s\"",
		arg_name_value);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
       if(ret < 0 ||row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_STA_UNEXIST;
       }	   

	if(sql){
		sqlite3_close(sql);
	}
		
	return 0;
}
int wipsd_sta_company_config(struct wipsd_sta_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];

	char *arg_name_value = (char *)&trans->name;
	char *arg_vendor_value = (char *)&trans->vendor;
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), 
		"update stalist set vendor=\"%s\" where name=\"%s\"",
		arg_vendor_value,wipsd_convert_star2space(arg_name_value));
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if(ret){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;
	}

	if(sql){
    		sqlite3_close(sql);
	}

	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_sta_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_IPC_OK;
	struct wipsd_sta_st *sta_st = (struct wipsd_sta_st *)buf;
	struct wipsd_sta_trans *trans = NULL;

	if(sta_st == NULL){
		vsos_assert(0);
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &sta_st->trans;
	switch(sta_st->cmd){
		case WIPSD_STA_ADD:
			ret = wipsd_sta_add(trans);
			break;
		case WIPSD_STA_DEL:
			ret = wipsd_sta_delete(trans);
			break;
		case WIPSD_STA_CONFIG:
			ret = wipsd_sta_config(trans);
			break;
		case WIPSD_STA_COMPANY_CONFIG:
			ret = wipsd_sta_company_config(trans);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	
	if(ret){
		*len = sizeof(ret);
	}
	
	return ret;
}

int wipsd_sta_dump_show
	(void *data, int n_columns, char** column_values, char** column_names)
{
	int fd = *((int *)data);
	char *outbuf = NULL;
	struct wipsd_sta_trans *trans = NULL;

	outbuf = (char *)sta_trans;
	trans = sta_trans + sta_line;
	if(send_len < sizeof(struct wipsd_sta_trans)){
		sta_data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd,  sta_data, OAM_BUF_LEN);
		memset(outbuf, 0, OAM_MAX_DATA_LEN);
		sta_data->datalen = 0;
		sta_line = 0;
		trans = sta_trans;
		send_len = OAM_MAX_DATA_LEN;
	}
	
	memset((void *)trans, 0, sizeof(struct wipsd_sta_trans));
	strncpy((void *)trans->name, (void *)column_values[0], sizeof(trans->name) - 1);
    if (strncmp(column_values[1], "any", 3))
	    wipsd_mac_colon_to_string((void *)trans->mac, (void *)column_values[1]);
    else 
        strlcpy((void *)trans->mac, (void *)column_values[1], sizeof(trans->mac));

	strncpy((void *)trans->vendor, (void *)column_values[3], sizeof(trans->vendor) - 1);
	sta_line++;
	send_len -= sizeof(struct wipsd_sta_trans);
	
	return 0;
}

int wipsd_sta_dump(char *buf, char *outbuf, int *len, int fd)
{
	int row = 0;
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg = NULL;
	char query[1024];

	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));
	struct wipsd_sta_trans *trans = (struct wipsd_sta_trans *)buf;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	 
	memset((void *)query, 0, sizeof(query));
	if(buf && (strlen((void *)trans->name) > 0)){
		snprintf(query,sizeof(query), "select * from stalist where name = \"%s\"",trans->name);
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_STA_UNEXIST;
		}
		
	}else{
		snprintf(query,sizeof(query), "select * from stalist");
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_STA_UNEXIST;
		}
	}

	sta_data = (struct oam_data_st *)data;
	sta_trans = (struct wipsd_sta_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;
	ret = sqlite3_exec(sql, query, wipsd_sta_dump_show, &fd, &errmsg);
	if(ret){
		sqlite3_close(sql);
		sta_line = 0;
		sta_data = NULL;
		sta_trans = NULL ;
		return WIPSD_ERR_SQL_PROCESS;
	}
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN- sizeof(struct wipsd_sta_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	sta_line = 0;
	sta_data = NULL;
	sta_trans = NULL ;
	if(sql){
		sqlite3_close(sql);
	}
	
	return ret;
}

int wipsd_sta_learn_dump(char *buf, char *outbuf, int *len, int fd)
{
	int send_len = 0;
	w_node_list * tmp_node = NULL;
	struct wipsd_sta_info_trans *trans = NULL;

	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));	

	trans = (struct wipsd_sta_info_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;

	if(sta_list_p == NULL && sta_list_tail == NULL){
		return WIPSD_OK;
	}
		
	for (tmp_node = sta_list_p; tmp_node != NULL;){
		if(send_len < sizeof(struct wipsd_sta_info_trans)){
			data->datalen = OAM_MAX_DATA_LEN - send_len;
			write(fd, data, OAM_BUF_LEN);//(OAM_MAX_DATA_LEN)-send_len+sizeof(struct oam_data_st)
			memset(outbuf, 0, OAM_MAX_DATA_LEN);
			data->datalen = 0;
			trans = (struct wipsd_sta_info_trans *)outbuf;
			send_len = OAM_MAX_DATA_LEN;
		}

		memset((void *)trans, 0, sizeof(struct wipsd_sta_info_trans));
		strncpy((void *)trans->name, (void *)tmp_node->b_frame.name, OBJ_SHORT_NAME_MAX_LEN);
		memcpy((void *)trans->mac, (void *)tmp_node->b_frame.mac, ETH_ALEN);
		memcpy(trans->bssid, tmp_node->b_frame.bssid, ETH_ALEN);
		strncpy((void *)trans->vendor,(void *) tmp_node->b_frame.vendor, OBJ_DATA_MAX_LEN);

		trans->band=tmp_node->b_frame.freq_band;
		trans->channel=tmp_node->b_frame.channel;
		trans->signal=tmp_node->b_frame.signal_average;
		trans->noise=tmp_node->b_frame.noise;
		trans->up_time=tmp_node->b_frame.up_time;
		trans->last_time=tmp_node->b_frame.last_time;
        trans->is_assoc2ap =tmp_node->b_frame.is_assoc2ap;
		strncpy((void*)trans->mode, (void*)wipsd_phy_mode(tmp_node->b_frame.phy_mode), OBJ_SHORT_NAME_MAX_LEN);
		strncpy((void*)trans->sec_type, (void*)tmp_node->b_frame.sec_type, OBJ_NAME_MAX_LEN);
		strncpy((void*)trans->vendor, (void*)tmp_node->b_frame.vendor, OBJ_DATA_MAX_LEN);
		
		trans++;
		send_len -= sizeof(struct wipsd_sta_info_trans);
		tmp_node= tmp_node->next;
	}
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN - sizeof(struct wipsd_sta_info_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	return WIPSD_OK;
}

#define OBJ_NL_BUFLEN 512
int wipsd_nl_send_obj (struct addr_obj_trans *address, enum nl_op_type type)
{
  	char buf[OBJ_NL_BUFLEN];
	int *op_type;
	struct addr_obj_trans *addr;
	int datalen;

	if(!address)
		return -1;
	
	memset(buf, 0, OBJ_NL_BUFLEN);
	op_type = (int *)buf;
	*op_type = type;
	datalen = sizeof(int);
	addr = (struct addr_obj_trans *)(op_type + 1);
	memcpy(addr, address, sizeof(struct addr_obj_trans));
	datalen += sizeof(struct addr_obj_trans);

	if(kernel_request(CTRL_OBJECT, buf, datalen, OBJ_NL_BUFLEN, NLM_F_ACK) < 0)
		return -1;

	op_type = (int *)buf;
	return *op_type;
}

int wipsd_wpolicy_edit_obj(u32 pid, enum nl_op_type cmd)
{
	char name[OBJ_NAME_MAX_LEN];
	struct addr_obj_trans trans;

	memset(name, 0, OBJ_NAME_MAX_LEN);
	snprintf(name, OBJ_NAME_MAX_LEN, "wireless%d", pid);	

	memset(&trans, 0, sizeof(struct addr_obj_trans));
	strncpy(trans.name, name, OBJ_NAME_LEN);
	trans.obj = MAC_ADDR;
	trans.dn_flag = 0;
	trans.data.type = IP_NOT_USED;
	return wipsd_nl_send_obj(&trans, cmd);
}

int wipsd_wpolicy_edit_obj_data(u32 pid, u8 *mac, int type, enum nl_op_type cmd)
{
	char name[OBJ_NAME_MAX_LEN];
	struct addr_obj_trans trans;

	memset(name, 0, OBJ_NAME_MAX_LEN);
	snprintf(name, OBJ_NAME_MAX_LEN, "wireless%d", pid);	

	memset(&trans, 0, sizeof(struct addr_obj_trans));
	strncpy(trans.name, name, OBJ_NAME_LEN);
	trans.obj = MAC_ADDR;
	trans.data.type = type;
	memcpy(trans.data.host_mac, mac, ETH_ALEN);
	return wipsd_nl_send_obj(&trans, cmd);
}

int wipsd_wpolicy_add(struct wipsd_policy_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0; 
	int row1 = 0;
	int row2= 0;
	int row3= 0;
	int col = 0;
	int oid = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg =NULL;
	char *pwnet = NULL;
	char *pap = NULL;
	char *psta = NULL;
	char query[1024];
	char arg_channel_value[8];

	char *arg_wnet_value = (char *)&trans->wnet;
	char *arg_ap_value = (char *)&trans->ap;
	char *arg_sta_value = (char *)&trans->sta;
	
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),"select * from wpolicy");
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if(ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_SQL_PROCESS;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query,sizeof(query), 
		"select * from wpolicy where pid=\"%d\"",trans->pid);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if(ret < 0 || row > 0){
		sqlite3_close(sql);
		return WIPSD_ERR_WPO_EXIST;
	}
	
	oid = trans->pid;
	memset((void *)arg_channel_value, 0, sizeof(arg_channel_value));
	snprintf(arg_channel_value,sizeof(arg_channel_value),"%d",trans->channel);

	if (strncmp((char *)trans->wnet,"any",3) != 0){
		memset((void *)query, 0, sizeof(query));
		snprintf(query,sizeof(query),
			"select * from wnet where name=\"%s\"",arg_wnet_value);
		ret = sqlite3_get_row( sql, query, &dbResult, &row1, &col, &errmsg);
		if(ret < 0 || row1 <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_WNET_UNEXIST;
		}
	}
	
	if (strncmp((char *)trans->ap,"any",3) != 0){
		memset((void *)query, 0, sizeof(query));
		snprintf(query,sizeof(query), 
			"select * from aplist where name=\"%s\"",arg_ap_value);
		ret = sqlite3_get_row( sql, query, &dbResult, &row2, &col, &errmsg);
		if(ret < 0 || row2 <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_AP_UNEXIST;
		}
	}

	if (strncmp((char *)trans->sta,"any",3) != 0){
		memset((void *)query, 0, sizeof(query));
		snprintf(query,sizeof(query), 
			"select * from stalist where name=\"%s\"",arg_sta_value);
		ret = sqlite3_get_row( sql, query, &dbResult, &row3, &col, &errmsg);
		if(ret < 0 || row3 <= 0 ){	
			sqlite3_close(sql);
			return WIPSD_ERR_STA_UNEXIST;
		}
	}

	pwnet = wipsd_convert_star2space(arg_wnet_value);
	pap = wipsd_convert_star2space(arg_ap_value);
	psta = wipsd_convert_star2space(arg_sta_value);
	memset((void *)query, 0, sizeof(query));
	/*ap_mac stand for ap name ,sta_mac stand for sta name*/
	snprintf(query,sizeof(query), 
		"insert into wpolicy (\"oid\", \"pid\", \"wnet\", \"ap_mac\",\"sta_mac\", \"wevent\", \"ctime\", \"waction\",\"enable\",\"channel\")"
		"values(\"%d\", \"%d\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\",\"%s\")",
		oid,trans->pid,pwnet,pap,psta,trans->wevent,"any",trans->waction,trans->enable, arg_channel_value);
	ret = sqlite3_exec(sql, query, NULL, NULL, &errmsg);
	if(ret != SQLITE_OK){
		return WIPSD_ERR_ADD_FAIL;
	}

	if(sql){
		sqlite3_close(sql);
	}

	if(!strncmp((char *)trans->waction, "deny", 4))
	{
		if(!strncmp((char *)trans->enable, "true", 4))
		{
			ret = wipsd_wpolicy_edit_obj(trans->pid, NL_ADD_ADDR_OBJ);
		}

		if(ret)
		{
			vsos_debug_out("wpolicy %d, action %s, enable %s, ret %d\n",
							trans->pid, trans->waction, trans->enable, ret);
		}
	}
	
	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wpolicy_enable(struct wipsd_policy_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query), 
		"update wpolicy set enable=\"%s\" where pid=\"%d\"",
		trans->enable,trans->pid);
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if (ret != SQLITE_OK){
		sqlite3_close(sql);
		return WIPSD_ERR_CONFIG_FAIL;	
	}

	if(sql){
		sqlite3_close(sql);
	}
	
	if(!strncmp((char *)trans->waction, "deny", 4))
	{
		if(!strncmp((char *)trans->enable, "true", 4))
		{
			ret = wipsd_wpolicy_edit_obj(trans->pid, NL_ADD_ADDR_OBJ);
		}
		else
		{
			ret = wipsd_wpolicy_edit_obj(trans->pid, NL_DEL_ADDR_OBJ);
		}

		if(ret)
		{
			vsos_debug_out("wpolicy %d, action %s, enable %s, ret %d\n",
							trans->pid, trans->waction, trans->enable, ret);
		}
	}
	
	wpolicy_update_tag = 1;
	return 0;
}

int wipsd_wpolicy_delete(struct wipsd_policy_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char query[1024];
	int row = 0;

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query,sizeof(query), 
		"select * from wpolicy where pid=\"%d\"",trans->pid);
	ret = sqlite3_get_row( sql, query, NULL, &row, NULL, NULL);
	if(ret < 0 || row <= 0 ){	
		sqlite3_close(sql);
		return WIPSD_ERR_WPO_UNEXIST;
	}

	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"delete from wpolicy where pid=\"%d\"", trans->pid);
	ret = sqlite3_exec(sql, query, NULL, NULL, NULL);
	if (ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_DEL_FAIL;	
	}
	
	if(sql){
		sqlite3_close(sql);
	}

	
	ret = wipsd_wpolicy_edit_obj(trans->pid, NL_DEL_ADDR_OBJ);
	if(ret)
	{
		vsos_debug_out("wpolicy %d, action %s, enable %s, ret %d\n",
						trans->pid, trans->waction, trans->enable, ret);
	}

	wpolicy_update_tag = 1;
	return 0;

}

int wipsd_wpolicy_config(struct wipsd_policy_trans *trans)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;  
	char *errmsg = NULL;
	char query[1024];

	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	
	memset((void *)query, 0, sizeof(query));
	snprintf(query, sizeof(query),
		"select * from wpolicy where pid=\"%d\"",trans->pid);
	ret = sqlite3_get_row( sql, query, &dbResult, &row, &col, &errmsg);
	if(ret < 0 ||row <= 0){
		sqlite3_close(sql);
		return WIPSD_ERR_WPO_UNEXIST;
	}	   

	if(sql){
		sqlite3_close(sql);
	}
		
	return 0;
}

int wipsd_wpolicy_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_IPC_OK;
	struct wipsd_policy_st *policy_st = (struct wipsd_policy_st *)buf;
	struct wipsd_policy_trans *trans = NULL;

	if(policy_st ==NULL){
		vsos_assert(0);
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &policy_st->trans;
	switch(policy_st->cmd){
		case WIPSD_POLICY_ADD:
			ret = wipsd_wpolicy_add(trans);
			break;
		case WIPSD_POLICY_DEL:
			ret = wipsd_wpolicy_delete(trans);
			break;
		case WIPSD_POLICY_CONFIG:
			ret = wipsd_wpolicy_config(trans);
			break;
		case WIPSD_POLICY_ENABLE:
			ret = wipsd_wpolicy_enable(trans);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	
	if(ret){
		*len = sizeof(ret);
	}
	
	return ret;
}

int wipsd_wpolicy_dump_show
	(void* data, int n_columns, char** column_values, char** column_names)
{	
	int fd = *((int *)data);
	char *outbuf = NULL;
	struct wipsd_policy_trans *trans = NULL;

	outbuf = (char *)wpolicy_trans;
	trans = wpolicy_trans + wpolicy_line;
	if(send_len < sizeof(struct wipsd_policy_trans)){
		wpolicy_data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd,  wpolicy_data, OAM_BUF_LEN);
		memset(outbuf, 0, OAM_MAX_DATA_LEN);
		wpolicy_data->datalen = 0;
		wpolicy_line = 0;
		trans = wpolicy_trans;
		send_len = OAM_MAX_DATA_LEN;
	}
	
	memset((void *)trans, 0, sizeof(struct wipsd_policy_trans));
	trans->pid = atoi(column_values[1]);
	strncpy((void *)trans->wnet, (void *)column_values[2], sizeof(trans->wnet) - 1);
	strncpy((void *)trans->ap, (void *)column_values[3], sizeof(trans->ap) - 1);
	strncpy((void *)trans->sta, (void *)column_values[4], sizeof(trans->sta) - 1);	
	strncpy((void *)trans->wevent, (void *)column_values[5], sizeof(trans->wevent) - 1);
	strncpy((void *)trans->waction, (void *)column_values[7], sizeof(trans->waction) - 1);
	strncpy((void *)trans->enable, (void *)column_values[8], sizeof(trans->enable) - 1);
	trans->channel = atoi(column_values[9]);
	wpolicy_line++;
	send_len -= sizeof(struct wipsd_policy_trans);

	return 0;
}

int wipsd_wpolicy_dump(char *buf, char *outbuf, int *len, int fd)
{
	int row = 0;
//	int col = 0;
	int ret = WIPSD_IPC_OK;
	sqlite3 *sql = NULL;
	char **dbResult = NULL;
	char *errmsg = NULL;
	char query[1024];

	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));
	struct wipsd_policy_trans *trans = (struct wipsd_policy_trans *)buf;

	
	ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}
	 
	memset((void *)query, 0, sizeof(query));
	if(buf && trans->pid != 0){
		snprintf(query,sizeof(query), "select * from wpolicy where pid=\"%d\"",trans->pid);
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_WPO_UNEXIST;
		}
		
	}else{
		snprintf(query,sizeof(query), "select * from wpolicy order by pid");
		ret = sqlite3_get_row( sql, query, &dbResult, &row, NULL, &errmsg);
		if (ret < 0 || row <= 0){
			sqlite3_close(sql);
			return WIPSD_ERR_WPO_UNEXIST;
		}
	}

	wpolicy_data = (struct oam_data_st *)data;
	wpolicy_trans = (struct wipsd_policy_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;
	ret = sqlite3_exec(sql, query,wipsd_wpolicy_dump_show, &fd, &errmsg);
	if(ret){
		sqlite3_close(sql);
		wpolicy_line = 0;
		wpolicy_data = NULL;
		wpolicy_trans = NULL;
		return WIPSD_ERR_WPO_EXIST;
	}
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN- sizeof(struct wipsd_policy_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	wpolicy_line = 0;
	wpolicy_data = NULL;
	wpolicy_trans = NULL;
	if(sql){
		sqlite3_close(sql);
	}
	
	have_wpolicy = 0;
	return ret;
}

int wipsd_wips_event_dump_show
	(void* data, int n_columns, char** column_values, char** column_names)
{
	int fd = *((int *)data);
	char *outbuf = NULL;

	struct wipsd_wips_event_trans *trans = NULL;

	outbuf = (char *)wips_event_trans;
	trans = wips_event_trans + wips_event_line;
	if(send_len < sizeof(struct wipsd_wips_event_trans)){
		wips_event_data->datalen  = OAM_MAX_DATA_LEN - send_len;
		write(fd,  wips_event_data, OAM_BUF_LEN);
		memset(outbuf, 0, OAM_MAX_DATA_LEN);
		wips_event_data->datalen = 0;
		wips_event_line = 0;
		trans = wips_event_trans;
		send_len = OAM_MAX_DATA_LEN;
	}

	memset((void *)trans, 0, sizeof(struct wipsd_wips_event_trans));
	trans->log_num = wips_log_num;
	strncpy((void *)trans->bssid, (void *)column_values[0], sizeof(trans->bssid) - 1);
	strncpy((void *)trans->mac, (void *)column_values[1], sizeof(trans->mac) - 1);
	strncpy((void *)trans->channel, (void *)column_values[2], sizeof(trans->channel) - 1);
	strncpy((void *)trans->alert, (void *)column_values[5], sizeof(trans->alert) - 1);
	strncpy((void *)trans->permit, (void *)column_values[6], sizeof(trans->permit) - 1);
	strncpy((void *)trans->pri, (void *)column_values[7], sizeof(trans->pri) - 1);
	strncpy((void *)trans->up_time, (void *)column_values[8], sizeof(trans->up_time) - 1);
	strncpy((void *)trans->name, (void *)column_values[13], sizeof(trans->name) - 1);
	strncpy((void *)trans->ssid, (void *)column_values[14], sizeof(trans->ssid) - 1);

	wips_log_num++;
	wips_event_line++;
	send_len -= sizeof(struct wipsd_wips_event_trans);
	
	return 0;
}

#ifndef MEMLOG
int wipsd_wips_event_dump(char *buf, char *outbuf, int *len, int fd)
{
	int ret = WIPSD_IPC_OK;
	int row = 0;
	int col = 0;
	int start = 0;
	int num = 0;
	char **dbResult  = NULL;
	sqlite3 *sql = NULL;
	char *errmsg = NULL;
	char query[1024];
	struct wipsd_wips_event_st *wips_event_st = (struct wipsd_wips_event_st *)buf;

	if(wips_event_st ==NULL){
		vsos_assert(0);
		ret = WIPSD_ERR_TRANS_FAULT;
		return WIPSD_ERR_TRANS_FAULT;
	}

	start = wips_event_st->start;
	num = wips_event_st->num;

	memset((void *)query, 0, sizeof(query));
	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));
	ret = sqlite3_open(WIPS_LOG_DB,&sql);
	if (ret != SQLITE_OK){
		return WIPSD_ERR_OPEN_FILE;
	}	

	ret = sqlite3_get_row( sql, 
		"select * from wips_event", &dbResult, &row, &col, &errmsg);
	if(ret < 0){
		sqlite3_close(sql);
		return WIPSD_ERR_SQL_PROCESS;
	}

	if (row == 0){
		return 0;
	}

	memset((void *)query, 0, sizeof(query));
#if 0	
	if(row - WIPSD_EVENT_MAX > 0){
		snprintf(query, sizeof(query),
			"select * from wips_event order by up_time desc limit %d offset %d",
			num , start);
	}else{
		snprintf(query, sizeof(query),
			"select * from wips_event order by up_time desc limit %d offset %d", row, 0);
	}
#endif
	if (num == 0){
		wips_log_num = 1;
		snprintf(query, sizeof(query),
			"select * from wips_event order by up_time desc limit %d offset %d", 
			WIPSD_EVENT_MAX, 0);
	}else{
		wips_log_num = start;
		snprintf(query, sizeof(query),
			"select * from wips_event order by up_time desc limit %d offset %d", 
			num, start);
	}
	
	wips_event_data = (struct oam_data_st *)data;
	wips_event_trans = (struct wipsd_wips_event_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;
	ret = sqlite3_exec(sql, query, wipsd_wips_event_dump_show, &fd , &errmsg);
	if(ret){
		sqlite3_close(sql);
		wips_event_line = 0;
		wips_event_data = NULL;
		wips_event_trans = NULL;
		return WIPSD_ERR_SQL_PROCESS;
	}
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN- sizeof(struct wipsd_wips_event_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}
	
	wips_event_line = 0;
	wips_event_data = NULL;
	wips_event_trans = NULL;
	if(sql){
		sqlite3_close(sql);
	}
	
	return 0;
}
#else

int wipsd_wips_event_dump(char *buf, char *outbuf, int *len, int fd)
{
	int ret = WIPSD_IPC_OK;
	int i = 0;
	int start = 0;
	int num = 0;
	int send_len = 0;
	int start_index = 0;
	int wips_log_num = 0;
	struct wipsd_wips_event_st *wips_event_st = (struct wipsd_wips_event_st *)buf;
	struct wipsd_wips_event_trans *trans = NULL;
	struct memlog_data_t *memlog_data = NULL;
	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));

	if(wips_event_st ==NULL){
		vsos_assert(0);
		ret = WIPSD_ERR_TRANS_FAULT;
		return WIPSD_ERR_TRANS_FAULT;
	}

	start = wips_event_st->start;
	num = wips_event_st->num;

	if (num == 0){
		start = 1;
		wips_log_num = 1;
		num = event_memlog.num - 1;
	}else if (num <= event_memlog.num){
		wips_log_num = start;
	}else{
		wips_log_num = start;
		num = event_memlog.num;
	}

	if (start > event_memlog.num){
		return 0;
	}

	if (start + num - 1 > event_memlog.num ){
		num = event_memlog.num - start;
	}

	trans = (struct wipsd_wips_event_trans *)outbuf;
	send_len = OAM_MAX_DATA_LEN;

	pthread_mutex_lock(&event_memlog_mutex);

	if ( event_memlog.cur != event_memlog.end ){
		
		if (event_memlog.start + start - 1 > event_memlog.cur ){
			pthread_mutex_unlock(&event_memlog_mutex);

			return 0;
		}else{
			if(event_memlog.cur - event_memlog.start - start < num){
				num = event_memlog.cur - event_memlog.start - start;

			}
		}
	}
	start_index = (event_memlog.cur - start - 1 + event_memlog.num)%event_memlog.num;

	for (i = start_index; num > 0;
				i = (i - 1 + event_memlog.num) %event_memlog.num, num-- ){

		if(send_len < sizeof(struct wipsd_wips_event_trans)){
			data->datalen = OAM_MAX_DATA_LEN - send_len;
			write(fd, data, OAM_BUF_LEN);//(OAM_MAX_DATA_LEN)-send_len+sizeof(struct oam_data_st)
			memset(outbuf, 0, OAM_MAX_DATA_LEN);
			data->datalen = 0;
			trans = (struct wipsd_wips_event_trans *)outbuf;
			send_len = OAM_MAX_DATA_LEN;
		}

		memset((void *)trans, 0, sizeof(struct wipsd_wips_event_trans));
		memlog_data = &event_memlog.log[i];
		trans->log_num = wips_log_num;
		strncpy((void *)trans->bssid, (void *)memlog_data->bssid, sizeof(trans->bssid) - 1);
		strncpy((void *)trans->mac, (void *)memlog_data->mac, sizeof(trans->mac) - 1);
		strncpy((void *)trans->channel, (void *)memlog_data->channel, sizeof(trans->channel) - 1);
		strncpy((void *)trans->alert, (void *)memlog_data->alert, sizeof(trans->alert) - 1);
		strncpy((void *)trans->permit, (void *)memlog_data->permit, sizeof(trans->permit) - 1);
		strncpy((void *)trans->pri, (void *)memlog_data->pri, sizeof(trans->pri) - 1);
		strncpy((void *)trans->up_time, (void *)memlog_data->up_time, sizeof(trans->up_time) - 1);
		strncpy((void *)trans->name, (void *)memlog_data->name, sizeof(trans->name) - 1);
		strncpy((void *)trans->ssid, (void *)memlog_data->ssid, sizeof(trans->ssid) - 1);

		trans++;
		send_len -= sizeof(struct wipsd_wips_event_trans);
		wips_log_num++;
	}
	pthread_mutex_unlock(&event_memlog_mutex);
	
	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN - sizeof(struct wipsd_wips_event_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}

	return 0;
}
#endif

int wipsd_config_dump(char *buf, char *outbuf, int *len, int fd)
{
	int send_len = OAM_MAX_DATA_LEN;
	struct wipsd_config_trans *trans = NULL;
	struct oam_data_st *data = 
		(struct oam_data_st *)(outbuf - sizeof(struct oam_data_st));
	struct list_head *pos = NULL;
	struct wipsd_interface *wipsd_if = NULL;
	struct wipsd_interface_trans *interface_trans = NULL;
	struct wipsd_log_trans *log_trans = NULL;

	trans = (struct wipsd_config_trans *)outbuf;
	memset((void *)trans, 0, sizeof(struct wipsd_config_trans));
	trans->type = WIPSD_CONFIG_INFO;
	trans++;
	send_len -= sizeof(struct wipsd_config_trans);

	memset((void *)trans, 0, sizeof(struct wipsd_config_trans));
	trans->type = WIPSD_CONFIG_SYS_LOG;
	log_trans = &trans->data.log;
	log_trans->log_type = log_mode;
	log_trans->syslog_ip = syslog_ip;
	log_trans->syslog_port = syslog_port;
	trans++;
	send_len -= sizeof(struct wipsd_config_trans);

	if(packet_syslog_out || wips_event_syslog_out)
	{
		memset((void *)trans, 0, sizeof(struct wipsd_config_trans));
		trans->type = WIPSD_CONFIG_WIPS_SYSLOG_OUT;
		log_trans = &trans->data.log;
		log_trans->log_type = packet_syslog_out;
		log_trans->syslog_ip = wips_event_syslog_out;
		//log_trans->syslog_port = syslog_port;
		trans++;
		send_len -= sizeof(struct wipsd_config_trans);
	}
	if(wipsd_itf_list->cnt){
		list_for_each(pos, &wipsd_itf_list->list){
			wipsd_if = list_entry(pos, struct wipsd_interface, list);
			if(!wipsd_if || !wipsd_if->itf){
				WIPSD_DEBUG("wipsd_if is null!\t\n");
				continue;
			}	

			if(send_len < sizeof(struct wipsd_config_trans)){
				data->datalen = OAM_MAX_DATA_LEN - send_len;
				write(fd, data, OAM_BUF_LEN);
				memset(outbuf, 0, OAM_MAX_DATA_LEN);
				data->datalen = 0;
				trans = (struct wipsd_config_trans *)outbuf;
				send_len = OAM_MAX_DATA_LEN;
			}
			
			memset((void *)trans, 0, sizeof(struct wipsd_config_trans));
			trans->type = WIPSD_INTERFACE_LIST_INFO;
			interface_trans = &(trans->data.interface);
			strncpy((void *)interface_trans->name, (void *)wipsd_if->itf->name, 
				sizeof(interface_trans->name) - 1);
			trans++;
			send_len -= sizeof(struct wipsd_config_trans);
		}
	}

	if((send_len != OAM_MAX_DATA_LEN )
		||(send_len != OAM_MAX_DATA_LEN- sizeof(struct wipsd_config_trans))){
		data->datalen = OAM_MAX_DATA_LEN - send_len;
		write(fd, data, OAM_BUF_LEN);
	}

	return 0;
}


//wips interface config
struct wipsd_interface *wips_config_interface_search(struct interface *itf, int *ret)
{
	struct list_head *pos = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	if(list_empty(&wipsd_itf_list->list)){
		return NULL;
	}
	
	list_for_each(pos, &wipsd_itf_list->list){
		wipsd_if = list_entry(pos, struct wipsd_interface, list);
		if(!wipsd_if || !wipsd_if->itf){
			*ret = WIPSD_ERR_UNKOWN;
			return NULL;
		}

		if(wipsd_if->itf == itf){
			*ret = WIPSD_ERR_INTERFACE_EXIST;
			return wipsd_if;
		}
	}

	return NULL;
}

int wips_config_interface_add(struct wipsd_interface_trans *trans)
{
	int ret = WIPSD_OK;
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	if(!strncmp((void *)trans->name, "lo", 2)){
		ret = WIPSD_ERR_INTERFACE_UNAVAILABLE;
		goto OUT;
	}

	itf = if_lookup_by_name((char *)trans->name);
	if(!itf){
		ret = WIPSD_ERR_INTERFACE_UNEXIST;
		goto OUT;
	}

	wips_config_interface_search(itf, &ret);
	if(ret){
		goto OUT;
	}

	wipsd_if = wipsd_if_create(itf);
	if(!wipsd_if){
		ret = WIPSD_ERR_MALLOC;
		goto OUT;
	}

	list_add(&wipsd_if->list, &wipsd_itf_list->list);
	wipsd_itf_list->cnt++;

	wipsd_if_start(wipsd_if);
OUT:		
	return ret;
}

int wips_config_interface_del(struct wipsd_interface_trans *trans)
{
	int ret = WIPSD_OK;
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	itf = if_lookup_by_name((char *)trans->name);
	if(!itf){
		ret = WIPSD_ERR_INTERFACE_UNEXIST;
		goto OUT;
	}

	wipsd_if = wips_config_interface_search(itf, &ret);
	if(!wipsd_if){
		goto OUT;
	}

	wipsd_if_destroy(wipsd_if);
	itf->info = NULL;
	list_del(&wipsd_if->list);
	XFREE(MTYPE_WIPSD_INTERFACE, wipsd_if);
	wipsd_itf_list->cnt--;
	
	return WIPSD_OK;
OUT:
	return ret;
}


int wips_config_interface_check_exist(struct wipsd_interface_trans *trans)
{
	struct list_head *pos = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	if(list_empty(&wipsd_itf_list->list)){
		return WIPSD_ERR_INTERFACE_UNEXIST;
	}
	
	list_for_each(pos, &wipsd_itf_list->list){
		wipsd_if = list_entry(pos, struct wipsd_interface, list);
		if(!wipsd_if->itf)
			continue;

		if(!strncmp((char *)trans->name,(char *)wipsd_if->itf->name,strlen((char *)trans->name))){
			return WIPSD_OK;
		}
	}

	return WIPSD_ERR_INTERFACE_UNEXIST;
}

int wips_interface_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
	struct wipsd_interface_st *config_st = (struct wipsd_interface_st *)buf;
	struct wipsd_interface_trans *trans = NULL;

	if(!config_st){
		WIPSD_DEBUG("have null parameter!\t\n");
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &config_st->trans;
	switch(config_st->cmd){
		case WIPSD_CONFIG_INTERFACE_ADD:
			ret = wips_config_interface_add(trans);
			break;
		case WIPSD_CONFIG_INTERFACE_DEL:
			ret = wips_config_interface_del(trans);
			break;
		case WIPSD_CONFIG_INTERFACE_CHECK_EXIST:
			ret = wips_config_interface_check_exist(trans);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

//wips debug config
int wips_config_debug_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
	struct wipsd_debug_st *config_st = (struct wipsd_debug_st *)buf;
	struct wipsd_debug_trans *trans = NULL;

	if(!config_st){
		WIPSD_DEBUG("have null parameter!\t\n");
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &config_st->trans;
	switch(config_st->cmd){
		case WIPSD_CONFIG_SET_DEBUG:
			wipsd_debug = trans->debug;
			break;
		case WIPSD_CONFIG_SHOW_DEBUG:
			trans->debug = wipsd_debug;
			*len = sizeof(struct wipsd_debug_st);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	

	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

int wipsd_config_log_set(struct wipsd_log_trans  *trans)
{	

	switch(trans->log_type){

		case WIPSD_LOG_TYPE_ALL:
			log_mode = 0;
			break; 
		case WIPSD_LOG_TYPE_LOCAL:
			log_mode = 1;
			break;
		case WIPSD_LOG_TYPE_REMOTE:
			log_mode = 2;
			break;
		default:
			WIPSD_DEBUG("Unkown log type!\n");
			return -1;
	}
	
	WIPSD_DEBUG("	set log mode %d\n", log_mode);
	
	return 0;
}

int wipsd_config_ip_port_set(struct wipsd_log_trans  *trans)
{

	if(trans->syslog_ip){
		WIPSD_DEBUG("	set syslog ip %s port %d \n",
			ip_ntoas(trans->syslog_ip),trans->syslog_port);
	}

	syslog_ip = trans->syslog_ip;
	syslog_port = trans->syslog_port;
	
	return 0;
}

int wipsd_config_log_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
	struct wipsd_log_trans_st *log_st = (struct wipsd_log_trans_st *)buf;
	struct wipsd_log_trans *trans = NULL;

	if(!log_st){
		WIPSD_DEBUG("have null parameter!\t\n");
		ret = WIPSD_ERR_TRANS_FAULT;
		goto OUT;
	}

	trans = &log_st->trans;
	switch(log_st->cmd){
		case WIPSD_CONFIG_LOG_SET:
			ret = wipsd_config_log_set(trans);
			break;
		case WIPSD_CONFIG_IP_PORT_SET:
			ret = wipsd_config_ip_port_set(trans);
			break;
		default:
			ret = WIPSD_ERR_UNKNOW_CMD;
			break;
	}
	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

int wipsd_config_signal_threshold_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
	WIPSD_DEBUG("signal_threshold is :%d!\t\n",signal_threshold);

	if(NULL != buf)
	{
		signal_threshold = *(int*)buf;
	}else{
		WIPSD_DEBUG("have null parameter!\t\n");
		goto OUT;
	}

	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}


int wipsd_config_wireless_node_age_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
		WIPSD_DEBUG("wireless_node_age is :%d!\t\n",wireless_node_age);

	if(NULL != buf)
	{
		wireless_node_age = *(int*)buf;
	}else{
		WIPSD_DEBUG("have null parameter!\t\n");
		goto OUT;
	}

	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

int wipsd_config_wireless_node_dead_time_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
			WIPSD_DEBUG("wireless_node_dead_time is :%d!\t\n",wireless_node_dead_time);

	if(NULL != buf)
	{
		wireless_node_dead_time = *(int*)buf;
	}else{
		WIPSD_DEBUG("have null parameter!\t\n");
		goto OUT;
	}

	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

int wipsd_config_wireless_show_all_info_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
			WIPSD_DEBUG("wireless_node_dead_time is :%d!\t\n",show_all_infor);

	if(NULL != buf)
	{
		show_all_infor = *(int*)buf;
	}else{
		WIPSD_DEBUG("have null parameter!\t\n");
		goto OUT;
	}

	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

int wipsd_config_wireless_set_packet_syslog_out_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
			WIPSD_DEBUG("wireless_node_dead_time is :%d!\t\n",packet_syslog_out);

	if(NULL != buf)
	{
		packet_syslog_out = *(int*)buf;
	}else{
		WIPSD_DEBUG("have null parameter!\t\n");
		goto OUT;
	}

	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}

int wipsd_config_wireless_set_event_syslog_out_handle(char *buf, char *outbuf, int *len)
{
	int ret = WIPSD_OK;
			WIPSD_DEBUG("wireless_node_dead_time is :%d!\t\n",wips_event_syslog_out);

	if(NULL != buf)
	{
		wips_event_syslog_out = *(int*)buf;
	}else{
		WIPSD_DEBUG("have null parameter!\t\n");
		goto OUT;
	}

	
OUT:	
	if(ret)
		*len = sizeof(ret);
	
	return ret;
}




struct oam_excute_st wipsd_oam_table[] = 
{
	[WIPSD_WNET_CONFIG] = { .doit = wipsd_wnet_handle },
	[WIPSD_WNET_DUMP] = { .dumpit = wipsd_wnet_dump },
	
	[WIPSD_AP_CONFIG] = { .doit = wipsd_ap_handle },
	[WIPSD_AP_DUMP] = { .dumpit = wipsd_ap_dump },
	[WIPSD_AP_LEARN_DUMP] = { .dumpit = wipsd_ap_learn_dump },
	
	[WIPSD_STA_CONFIG] = { .doit = wipsd_sta_handle },
	[WIPSD_STA_DUMP] = { .dumpit = wipsd_sta_dump },
	[WIPSD_STA_LEARN_DUMP] = { .dumpit = wipsd_sta_learn_dump },

	[WIPSD_POLICY_CONFIG] = { .doit = wipsd_wpolicy_handle },
	[WIPSD_POLICY_DUMP] = { .dumpit = wipsd_wpolicy_dump },
	
	[WIPSD_WIPS_EVENT_DUMP] = { .dumpit = wipsd_wips_event_dump },
	
	[WIPSD_CONFIG_DUMP] = { .dumpit = wipsd_config_dump },

	[WIPSD_CONFIG_INTERFACE] = { .doit = wips_interface_handle },

	[WIPSD_CONFIG_DEBUG] = { .doit = wips_config_debug_handle },

	[WIPSD_CONFIG_LOG] = {.doit = wipsd_config_log_handle},
	
	[WIPSD_SET_SIGNAL_THRESHOLD_LOG] = {.doit = wipsd_config_signal_threshold_handle},
	
	[WIPSD_SET_WIRELESS_AGE] = {.doit = wipsd_config_wireless_node_age_handle},
	
	[WIPSD_SET_WIRELESS_DEAD_TIME] = {.doit = wipsd_config_wireless_node_dead_time_handle},

	[WIPSD_SET_SHOW_ALL_INFO] = {.doit = wipsd_config_wireless_show_all_info_handle},

	[WIPSD_SET_PACKET_SYSLOG_OUT] = {.doit = wipsd_config_wireless_set_packet_syslog_out_handle},

	[WIPSD_SET_EVENT_SYSLOG_OUT] = {.doit = wipsd_config_wireless_set_event_syslog_out_handle},



};

void wipsd_init_vty(void)
{
	oam_execute = wipsd_oam_table;
}
