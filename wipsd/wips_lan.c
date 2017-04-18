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
#include "regex-gnu.h"
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include "ieee80211.h"
#define HLS_CONFIG 1
#ifndef HLS_CONFIG
#include "sys/hls_ioctl.h"
#include "sys/hls_config_util.h"
#endif
#include "hash.h"
#include "sqlite3.h"
#include "wdisp.h"
#include "wipsd_wnode.h"
//#include "wipsd.h"

#define HOSTSDB "/usr/hls/log/log/hosts.db"

#define P(x) ((x != NULL)?(x):"")

#define MAXLINE 255

extern int wireless_enable;
extern int lan_mon_enable;
extern int lan_mon_gap;
extern char lan_mon_if[128];
extern char lan_mon_net[128];
extern int active_lan_monitor;
extern int get_wireless_config(void);
extern int sqlite3_get_row( sqlite3 *sql, const char *query, char ***dbResult, int *row, int *col, char **errmsg);
extern int report_wips_event(struct w_node *node, int event);

sqlite3 *sql;
//int errno;
int table_num = 0;
int deceived_num = 0;
static struct hash_control *vendor_hash_table;
struct vendor_node *ap_vendor;
struct vendor_node *sta_vendor;
int vendor_num = 0;
char *ip_addr_t = NULL;

#ifndef HLS_CONFIG
#if 0
int gen_get_stats(int type, __u32 id, char *name, char **getbuf, int *getbuflen)
{
	struct hls_req req;
	char *buffer;
	int len, rt_len;
	int fd, ret;

	fd = open("/proc/ar/arctl", O_RDONLY);
	if (fd < 0)
		return -1;

/*	if(*getbuflen == 0)
		len = 1 << 20;
	else
		len = *getbuflen;
*/
	len = 1 << 21;
	bzero(&req, sizeof(req));
	buffer = malloc(len);

	req.cmd = type;
	req.id = id;
	if (name)
		strncpy(req.name, name, MAX_NAME_LENGTH - 1);

retry:

	req.base = buffer;
	req.len = len;
	req.rt_len = &rt_len;

	ret = ioctl(fd, HLS_CMD_GSTATS, &req);
	if (ret) {
		if (errno == EAGAIN) {
			wipsd_free(buffer);
			buffer = malloc(rt_len + 1);
			len = rt_len + 1;
			goto retry;
		} else {
			wipsd_free(buffer);
			close(fd);
			return -1;
		}
	}

	*getbuf = buffer;
	*getbuflen = rt_len;
	close(fd);

	return rt_len;
}
#endif
#if 0
int log_ip_dbase(void)
{
	char *buf;
	int buflen, total,ret, i, row, column;
	struct wips_elem *tn;

	char mac[32], up_time[32], last_time[32];
	char query[512];

	char **result;
	char *errmsg;

	sqlite3 *sql_hosts = NULL;
	sqlite3 *sql_beacon = NULL;

	buflen = 0;
	ret = gen_get_stats(STATS_TYPE_WIPS_MAC, 0, NULL, &buf, &buflen);
	if (ret < 0) {
		WIPSD_DEBUG("ioctl get hnode flow_log failed. errno=%d\n", errno);
		return ret;
	}

	tn = (struct wips_elem *)buf;
	total = buflen / sizeof(struct wips_elem);

	tn = (struct wips_elem *)buf;

	ret = sqlite3_open("/usr/hls/log/log/hosts.db",&sql_hosts);

	if(ret != SQLITE_OK) {
		wipsd_free(buf);
		WIPSD_DEBUG("open sqlite table hosts.db failed!");
		return ret;
	}

	ret = sqlite3_open("/usr/hls/log/log/beacon_test.db",&sql_beacon);

	if(ret != SQLITE_OK) {
		wipsd_free(buf);
        
        if(sql_hosts)
    		wipsd_sqlite3_close(sql_hosts);
        
		WIPSD_DEBUG("open sqlite table sql_beacon.db failed!");
		return ret;
	}

	for (i = 0; i < total; i++) {

//		sprintf(up_time,"%d",JIFFIES_TO_NS(tn->create_time));
//		sprintf(last_time, "%d", JIFFIES_TO_NS(tn->last));

		if(tn->macbind)
			sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",
				tn->bindmac[0],tn->bindmac[1],tn->bindmac[2],tn->bindmac[3],tn->bindmac[4],tn->bindmac[5]);
		else
			sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",
				tn->mac[0],tn->mac[1],tn->mac[2],tn->mac[3],tn->mac[4],tn->mac[5]);

		sprintf(query, "select * from ip where mac=\"%s\"", mac);
		ret = sqlite3_get_row( sql_hosts, query, &result, &row, &column, &errmsg );

		if(row > 0) {
			sprintf(query, "update ip set ipaddr=\"%s\", name=\"%s\", dep=\"%s\", up_time=\"%s\", last_time=\"%s\" where mac=\"%s\"",
				inet_ntoa(*(struct in_addr *)&tn->ip), tn->name, tn->department, P(up_time), P(last_time), mac);
			ret = sqlite3_exec(sql_hosts, query, NULL, NULL , NULL);
		}
		else {
			sprintf(query, "insert into ip (\"ipaddr\",\"mac\",\"name\",\"dep\",\"up_time\",\"last_time\") "
				"values (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")",
				inet_ntoa(*(struct in_addr *)&tn->ip), mac, tn->name, tn->department, P(up_time), P(last_time));
			ret = sqlite3_exec(sql_hosts, query,NULL, NULL , NULL);
		}

		sprintf(query, "update beacon_test1 set ipaddr=\"%s\" where mac=\"%s\"",
				inet_ntoa(*(struct in_addr *)&tn->ip), mac);
		ret = sqlite3_exec(sql_beacon, query, NULL, NULL , NULL);

		sprintf(query, "update sta_list set ipaddr=\"%s\" where mac=\"%s\"",
				inet_ntoa(*(struct in_addr *)&tn->ip), mac);
		ret = sqlite3_exec(sql_beacon, query, NULL, NULL , NULL);

		tn++;
	}

	wipsd_free(buf);
    if(sql_hosts)
    	wipsd_sqlite3_close(sql_hosts);

    if(sql_beacon)
    	wipsd_sqlite3_close(sql_beacon);

	return 0;
}
#endif
#endif

char *find_mac_vendor(char *mac)
{
	char oui_string[13];	/* Space for full hw addr plus NULL */
	char *vendor=NULL;
	int oui_end=9;
	int i,j=0;

	for(i=0; i<17; i++) {
		if(mac[i] == '\0') {
			break;
		}

		if(mac[i] != ':') {
			oui_string[j] = toupper(mac[i]);
			j++;
		}
	}
	oui_string[j] = '\0';

	while (vendor == NULL && oui_end > 1) {
	 oui_string[oui_end] = '\0';	/* Truncate oui string */
	 vendor = hash_find(vendor_hash_table, oui_string, 0);
	 oui_end--;
	}
	if(vendor)
		return vendor;
	else
		return "Unknown";
}

int get_ip_from_hostdb(void* data, int n_columns, char** column_values, char** column_names)
{

	if(column_values[0]) {
		ip_addr_t =  XMALLOC(MTYPE_WIPS_DEBUG_FIND_LAN_IP,32);
		memset(ip_addr_t, 0, 32);
		strncpy(ip_addr_t, column_values[0], 32);
	}

	return 0;
}

int check_arp_proxy(void* data, int n_columns, char** column_values, char** column_names)
{
	if(!column_values[0])return 0;
	if(n_columns== 1){
		switch(*((int*)data)){
			case 1:
				table_num = atoi(column_values[0]);
				break;
			case 2:
				deceived_num = atoi(column_values[0]);
				break;
			default :
				break;
		}
	}
	return 0;
}
int get_ip_from_wconfigdb(void* data, int n_columns, char** column_values, char** column_names)
{

	if(column_values[2]) {
		ip_addr_t =  XMALLOC(MTYPE_WIPS_DEBUG_FIND_LAN_IP,32);
		memset(ip_addr_t, 0, 32);
		strncpy(ip_addr_t, column_values[2], 32);
	}

	return 0;
}

//pthread_mutex_t	fflag = PTHREAD_MUTEX_INITIALIZER;

char *find_lan_ip(char *mac, char **ip)
{
	sqlite3 *sql = NULL;
	int ret;
	char query[256];
//	char *ip_addr = NULL;

//	sqlite3_stmt *stmt;
//	const char *tail;
//	WIPSD_DEBUG("func:%s ,line:%d (!p_oflist->b_frame.ipv4[0])",__func__,__LINE__);

	*ip = NULL;

	if(!mac || mac[0] == '\0')
	{
	WIPSD_DEBUG("func:%s ,line:%d  reuturn NULL\n",__func__,__LINE__);
		return NULL;
	}

	if(active_lan_monitor) {
		#if 0
		/* get from hostsdb */
		ret = sqlite3_open(HOSTSDB, &sql);
		if(ret == SQLITE_OK) {

			sprintf(query, "select * from ip where mac=\"%s\"", mac);
			sqlite3_exec(sql, query, get_ip_from_hostdb, NULL , NULL);

/*			rc = sqlite3_prepare(sql, query, -1, &stmt, &tail);
			if (rc != SQLITE_OK)
			{
				fprintf(stderr, "sql error:%s\n", sqlite3_errmsg(sql));
				goto end;
			}
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_ROW)
			{
				if(sqlite3_column_text(stmt, 0)) {

					ip_addr =  malloc(32);
					if(ip_addr == NULL) {
						goto end;
					}
					
					memset(ip_addr, 0, 32);
					strncpy(ip_addr, sqlite3_column_text(stmt, 0), 32);
				}
			}
			sqlite3_finalize(stmt);*/

            if(sql)
    			wipsd_sqlite3_close(sql);
		} else {

			WIPSD_DEBUG("open sqlite table hosts.db failed!");
		}
#endif
		/* if can not find in hostsdb, find it in wconfigdb */
			ret = sqlite3_open(WIPS_WCONFIG_DB, &sql);
			if(ret == SQLITE_OK) {

				sprintf(query, "select * from aplist where wmac=\"%s\" and type=\"internalap\"", mac);
	//			WIPSD_DEBUG("func:%s ,line:%drun sqlite3 :%s !\t\n",__func__,__LINE__,query);

				sqlite3_exec(sql, query, get_ip_from_wconfigdb, NULL , NULL);

				/*rc = sqlite3_prepare(sql, query, -1, &stmt, &tail);
				if (rc != SQLITE_OK)
				{
					fprintf(stderr, "sql error:%s\n", sqlite3_errmsg(sql));
					goto end;
				}
				rc = sqlite3_step(stmt);
				if (rc == SQLITE_ROW)
				{
					if(sqlite3_column_text(stmt, 2)) {
						ip_addr =  malloc(32);

						if(ip_addr == NULL) {
							goto end;
						}
											
						memset(ip_addr, 0, 32);
						strncpy(ip_addr, sqlite3_column_text(stmt, 2), 32);
					}
				}
				sqlite3_finalize(stmt);*/

                if(sql)
    				wipsd_sqlite3_close(sql);
			} else {

				WIPSD_DEBUG("open sqlite table wconfig.db failed!");
			}
		}
	
	
	if(ip_addr_t != NULL ) {
		if(ip_addr_t[0]!=0){
		*ip = XMALLOC(MTYPE_WIPS_DEBUG_FIND_LAN_IP,32);
		

		memset(*ip, 0, 32);
		strcpy(*ip, ip_addr_t);
		//WIPSD_DEBUG("func:%s get the ip of %s, ip:%s !\t\n",__func__,mac,*ip);
		}
		XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip_addr_t);
		ip_addr_t = NULL;

		return *ip;
		
	}
	else
		{
//	WIPSD_DEBUG("func:%s ,line:%d  reuturn NULL\n",__func__,__LINE__);
		return NULL;
	}

	return NULL;

//end:
	
//	sqlite3_finalize(stmt);
//	wipsd_sqlite3_close(sql);
	return NULL;
}

int add_mac_vendor(struct hash_control *table, const char *map_filename) {
	static int first_call=1;
	FILE *fp;	/* MAC/Vendor file handle */
	static const char *oui_pat_str = "([^\t]+)\t[\t ]*([^\t\r\n]+)";
	static regex_t oui_pat;
	regmatch_t pmatch[3];
	size_t key_len;
	size_t data_len;
	char *key;
	char *data;
	char line[MAXLINE];
	int line_count;
	int result;
	const char *result_str;
	/*
	*	Compile the regex pattern if this is the first time we
	*	have been called.
	*/
	if (first_call) {
	  first_call=0;
	  if ((result=regcomp(&oui_pat, oui_pat_str, REG_EXTENDED))) {
		 char reg_errbuf[MAXLINE];
		 size_t errlen;
		 errlen=regerror(result, &oui_pat, reg_errbuf, MAXLINE);
		 WIPSD_DEBUG("ERROR: cannot compile regex pattern \"%s\": %s",
				 oui_pat_str, reg_errbuf);
	  }
	}
	/*
	*	Open the file.
	*/
	if ((fp = fopen(map_filename, "r")) == NULL) {
	  WIPSD_DEBUG("WARNING: Cannot open MAC/Vendor file %s", map_filename);
	  return 0;
	}
	line_count=0;
	/*
	*
	*/
	while (fgets(line, MAXLINE, fp)) {
		if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
			continue;	/* Skip blank lines and comments */
		result = regexec(&oui_pat, line, 3, pmatch, 0);
		if (result == REG_NOMATCH || pmatch[1].rm_so < 0 || pmatch[2].rm_so < 0) {
			WIPSD_DEBUG("WARNING: Could not parse oui: %s", line);
		} else if (result != 0) {
			char reg_errbuf[MAXLINE];
			size_t errlen;
			errlen=regerror(result, &oui_pat, reg_errbuf, MAXLINE);
			WIPSD_DEBUG("ERROR: oui regexec failed: %s", reg_errbuf);
		} else {
			key_len = pmatch[1].rm_eo - pmatch[1].rm_so;
			data_len = pmatch[2].rm_eo - pmatch[2].rm_so;
			key=malloc(key_len+1);
			data=malloc(data_len+1);
			/*
			* We cannot use strlcpy because the source is not guaranteed to be null
			* terminated. Therefore we use strncpy, specifying one less that the total
			* length, and manually null terminate the destination.
			*/
			strncpy(key, line+pmatch[1].rm_so, key_len);
			key[key_len] = '\0';
			strncpy(data, line+pmatch[2].rm_so, data_len);
			data[data_len] = '\0';
			if ((result_str = hash_insert(table, key, 0, data)) != NULL) {
				/* Ignore "exists" because there are a few duplicates in the IEEE list */
				if ((strcmp(result_str, "exists")) != 0) {
					WIPSD_DEBUG("hash_insert(%s, %s): %s", key, data, result_str);
				}
			} else {
				line_count++;
			}
		}
	}
	fclose(fp);
	return line_count;
}

int whandle_get_ap_mac(void* data, int n_columns, char** column_values, char** column_names)
{
	char upper[24];
	int i,j = 0;

	vendor_num--;

	if(vendor_num < 0) return 0;
	if(!column_values[1]) return 0;

	ap_vendor[vendor_num].mac[23] = '\0';
	ap_vendor[vendor_num].vendor[127] = '\0';
	upper[23] = '\0';

	strncpy(ap_vendor[vendor_num].mac, column_values[1], 23);

	for(i=0; i<23; i++) {
		if(ap_vendor[vendor_num].mac[i] == '\0') {
			break;
		}

		if(ap_vendor[vendor_num].mac[i] != ':') {
			upper[j] = toupper(ap_vendor[vendor_num].mac[i]);
			j++;
		}
		if(j>=23) {
			upper[j] = '\0';
			break;
		}
	}
	upper[j] = '\0';
	strncpy(ap_vendor[vendor_num].vendor, P(find_mac_vendor(upper)),127);
//	WIPSD_DEBUG("AP%d:  %s,  %s  %s\n",vendor_num, ap_vendor[vendor_num].mac, upper, ap_vendor[vendor_num].vendor);

	return 0;
}

int whandle_get_sta_mac(void* data, int n_columns, char** column_values, char** column_names)
{
	char upper[24];
	int i,j = 0;

	vendor_num--;

	if(vendor_num < 0) return 0;
	if(!column_values[1]) return 0;

	sta_vendor[vendor_num].mac[23] = '\0';
	upper[23] = '\0';
	sta_vendor[vendor_num].vendor[127] = '\0';

	strncpy(sta_vendor[vendor_num].mac, column_values[1], 23);

	for(i=0; i<24; i++) {
		if(sta_vendor[vendor_num].mac[i] == '\0') {
			break;
		}

		if(sta_vendor[vendor_num].mac[i] != ':') {
			upper[j] = toupper(sta_vendor[vendor_num].mac[i]);
			j++;
		}
	}
	upper[j] = '\0';
	strncpy(sta_vendor[vendor_num].vendor, P(find_mac_vendor(upper)),127);

//	WIPSD_DEBUG("STA%d:  %s,  %s  %s\n",vendor_num, sta_vendor[vendor_num].mac, upper,sta_vendor[vendor_num].vendor);
	return 0;
}

/*
int read_wireless_config(void* data, int n_columns, char** column_values, char** column_names)
{

	if(column_values[0])
		wireless_enable = atoi(column_values[0]);

	if(column_values[5])
		lan_mon_enable = atoi(column_values[5]);

	if(column_values[6])
		strncpy(lan_mon_if, column_values[6], 128);

	if(column_values[7])
		strncpy(lan_mon_net, column_values[7], 128);

	if(column_values[8])
		lan_mon_gap = atoi(column_values[8]);

	return 0;
}

int get_wireless_config()
{
	sqlite3 *sql;
	int ret;

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("open sqlite wconfig.db error !");
		return -1;
	}

	ret = -sqlite3_exec(sql, "select * from wpara", read_wireless_config, NULL,NULL);

	wipsd_sqlite3_close(sql);
	return ret;
}
*/
int init_vendor_hash_table(void)
{
	int count = 0;

	if ((vendor_hash_table = hash_new()) == NULL)
		WIPSD_DEBUG("hash_new failed");

	count = add_mac_vendor(vendor_hash_table, "/usr/local/etc/wips/ieee-oui.txt");
	if(count < 1){
		WIPSD_DEBUG("load oui failed");
		return -1;
	}
	
	count = add_mac_vendor(vendor_hash_table, "/usr/local/etc/wips/ieee-iab.txt");
	if(count < 1){
		WIPSD_DEBUG("load iab failed");
		return -1;

	}
	
	count = add_mac_vendor(vendor_hash_table, "/usr/local/etc/wips/mac-vendor.txt");
	if(count < 1){
		WIPSD_DEBUG("load vendor failed");
		return -1;
	}
	
	return 0;
}

int destory_vendor_hash_table(void)
{
	hash_die(vendor_hash_table);
	return 0;
}

int do_active_lan_mon_period(void)
{
	char cmd[256], ifa[128], net[256];
	sqlite3 *sql_hosts = NULL;
	int ret;
	int count = 0;

//	log_ip_dbase();

	strcpy(ifa, lan_mon_if);
	strcpy(net, lan_mon_net);

	while(wireless_enable && lan_mon_enable  && active_lan_monitor) {
		
		count++;
		get_wireless_config();

		if(/*count > 100 || */strcmp(ifa, lan_mon_if) != 0 || strcmp(net, lan_mon_net) != 0) {

			strcpy(ifa, lan_mon_if);
			strcpy(net, lan_mon_net);
//			count++;

			ret = sqlite3_open(HOSTSDB, &sql_hosts);
			if(ret == SQLITE_OK) {
				sqlite3_exec(sql_hosts, "delete from ip",NULL, NULL , NULL);
				sqlite3_exec(sql_hosts, "VACUUM",NULL, NULL , NULL);

				if(sql_hosts){
		    			wipsd_sqlite3_close(sql_hosts);
					sql_hosts = NULL;
				}
			}
			else {
				WIPSD_DEBUG("open sqlite table hosts.db failed!");
			}
		}


		sprintf(cmd,"active_mon --interface=%s %s", lan_mon_if, lan_mon_net);
		ret = system(cmd);

		ret = sqlite3_open(HOSTSDB, &sql_hosts);
		if(ret == SQLITE_OK) {
			ret = 1;
			sqlite3_exec(sql_hosts, 
				"select count(*) from ip", 
				check_arp_proxy, &ret , NULL);
			ret = 2;
			sqlite3_exec(sql_hosts, 
				"select count(*) from ip where mac in ( select mac from ip group by mac having(count(*))>1 )", 
				check_arp_proxy, &ret , NULL);
			if(deceived_num > 0){
				if(table_num == deceived_num){
					WIPSD_DEBUG("MITM attack!\n");
					report_wips_event(NULL, WIPS_EID_MITM_ATTACK);
				}else{
					WIPSD_DEBUG("ARP attack!\n");
					report_wips_event(NULL, WIPS_EID_ARP_SPOOFING_ATTACK);
				}
			}
			table_num = deceived_num = 0;
			if(sql_hosts){
				wipsd_sqlite3_close(sql_hosts);
				sql_hosts = NULL;
			}
		}
		sleep(lan_mon_gap * 60);
	}

	return 0;

}


