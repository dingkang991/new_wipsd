#if 0

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
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <math.h>
#include "sqlite3.h"
#include <sys/hls_config.h>
#include "hash.h"
#include "ieee80211.h"
#include "wipsd_wnode.h"
#include "wipsd.h"
#include "checklist.h"
#include "sys/wipsd_save.h"
#include "debug.h"
DEBUG_HOOK(1)

int period = 24*6;
char *period_str = "10分钟";

#define MAX (sizeof(struct w_node)*200 + 4)

#define PATH "/tmp/wireless_s"
#define C_PATH "/tmp/"

#define min(x,y) ((x) < (y) ? x : y)
#define P(x) ((x != NULL)?(x):"")

#define AP_PIX_X 32
#define AP_PIX_Y 32
#define STA_PIX_X 16
#define STA_PIX_Y 16

#define PRI_RED 2
#define PRI_YELLOW 1
#define PRI_GREEN 0

#define CHANNEL_5G_NUM 42
int const channel_5g[CHANNEL_5G_NUM]={7,8,9,11,12,16,34,36,38,40,42,44,46,48,52,56,60,64,
									100,104,108,112,116,120,124,128,132,136,140,149,153,
									157,161,165,183,184,185,187,188,189,192,196};

char *type = NULL;
char *name = NULL;
unsigned int id;

int topN = 0;
int limit = 30;
int start = 0;
int total = 0;

int pgWidth,pgHeight;
int wips_log_num = 0;

int all_ap_num;
int all_sta_num;
int in_ap_num;
int ex_ap_num;
int in_sta_num;
int ex_sta_num;
int al_sta_num;

int in_ssid_num;
int ex_ssid_num;

int empty_5g;
int empty_2g;

short id_index, id_unknown, parent;
int sta_px,sta_py,sta_step_x,sta_step_y,sta_row_num,sta_column_num,x_start, y_start=0;

int sql_table_row;

#ifdef MIPS
#include "wipsd_wnode.h"
#include "sys/lfd_log.h"
#include <sys/shm.h>
#include "event_mem_log.h"
#include "memshare.h"
#endif
int get_wevent_name(int);
int get_wevent_pri(int);

int h_sqlite3_get_row(void* data, int n_columns, char** column_values, char** column_names)
{
    sql_table_row++;
	return 0;
}

int sqlite3_get_row( sqlite3 *sql, const char *query, char ***dbResult, int *row, int *col, char **errmsg)
{
    int ret;

    if(sql == NULL)
        return 0;

    sql_table_row = 0;
    ret = sqlite3_exec(sql, query, h_sqlite3_get_row, NULL,NULL);

    *row = sql_table_row;

    return sql_table_row;
}

char *wevent_name = NULL;
char *wevent_pri = NULL;
char wevent_buf[(WEVENT_NAME_LEN + 1) * WIPS_EID_MAX];
char stats_ssid[256];

wevent_struct	*wevent_list = NULL;
int wevent_num = 0;
int wevent_index = 0;
int wevent_grp_num = 0;

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

	wevent_index++;
	return 0;
}

int init_wevent_list()
{
	int ret,row=0,col=0;
	char **dbResult;
	char *errmsg;
	sqlite3 *sql = NULL;

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		printf("open sqlite wconfig.db error !");
		return 0;
	}

	ret = sqlite3_get_row( sql, "select * from wevent", &dbResult, &row, &col, &errmsg);

	if(row > 0 ) {
		wevent_num = row;
		wevent_list = calloc(row,sizeof(struct wevent_struct));
		if(!wevent_list) {
            if(sql)
               sqlite3_close(sql);

			printf("no memory!");
			return 0;
		}

		wevent_index = 0;
		ret = sqlite3_exec(sql, "select * from wevent", get_wevent, NULL,NULL);
		if(ret != SQLITE_OK)
			goto error;
	}
	else
		goto error;

	ret = sqlite3_get_row( sql, "select * from wevent where is_grp=\"1\"", &dbResult, &row, &col, &errmsg);

	wevent_grp_num = row - 1;

    if(sql)
	    sqlite3_close(sql);
	return 0;

error:

    if(sql)
    	sqlite3_close(sql);
	return -1;
}

int destory_wevent_list()
{
	if(wevent_list)
		free(wevent_list);

	wevent_list =  NULL;
	return 0;
}

void printf_style(void)
{
	printf("<styles>"
			"<definition>"
				"<style name='myCaptionFont' type='font' font='Arial' size='12' color='666666' bold='1' underline='0'/>"
				"<style name='mySubCaptionFont' type='font' font='Arial' size='12' color='666666' italic='0' bold='0'/>"
				"<style name='myAxisTitlesFont' type='font' font='Arial' size='11' bold='1'/>"
			"</definition>"
			"<application>"
				"<apply toObject='Caption' styles='myCaptionFont' />"
				"<apply toObject='SubCaption' styles='mySubCaptionFont' />"
				"<apply toObject='XAxisName' styles='myAxisTitlesFont' />"
			"</application>"
			"</styles>");

}

char *deal_ssid(char *ssid)
{
    int i = 0;

    while(*(ssid + i) != '\0' && i < SSID_BUFSIZE_D) {

        switch (*(ssid + i)){
            case  '>':
            case  '<':
            case '\"':
            case '\'':
            case '\\':
			case '\r':
			case '\n':

                *(ssid + i) = '?';
                break;
            default:
                break;
        }
        i++;
    }

    return ssid;
}

char *get_stats_ssid(struct w_node *node)
{
	int start = 0, len = 0;

	memset(stats_ssid, 0, 256);

	if(node->ssid[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid);
		strncpy(&stats_ssid[start], node->ssid, len);
		start += len;
		goto end;
	}

	if(node->ssid2[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid2);
		strncpy(&stats_ssid[start], node->ssid2, len);
		start += len;
		goto end;
	}

	if(node->ssid3[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid3);
		strncpy(&stats_ssid[start], node->ssid3, len);
		start += len;
		goto end;
	}

	if(node->ssid4[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid4);
		strncpy(&stats_ssid[start], node->ssid4, len);
		start += len;
		goto end;
	}

	if(node->ssid5[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid5);
		strncpy(&stats_ssid[start], node->ssid5, len);
		start += len;
		goto end;
	}

	if(node->ssid6[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid6);
		strncpy(&stats_ssid[start], node->ssid6, len);
		start += len;
		goto end;
	}

	if(node->ssid7[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid7);
		strncpy(&stats_ssid[start], node->ssid7, len);
		start += len;
		goto end;
	}

	if(node->ssid8[0] != '\0') {
		if(start > 0) {
			stats_ssid[start] = '\n';
			start++;
		}

		len = strlen(node->ssid8);
		strncpy(&stats_ssid[start], node->ssid8, len);
		start += len;
		goto end;
	}
end:
	stats_ssid[start] = '\0';
	return stats_ssid;
}

static __u32 test_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] )
{
	int index;
	index = eid / 32;
	eid = eid % 32;
	if(index < ALERT_LEN)
		return ((*ev_map)[index] & ( 1UL << eid));
	else
		return 0;
}

int get_wevent_buf_by_wnode(struct w_node *node)
{
	int i, first = 0, len = 0;

	memset(&wevent_buf[0], 0, (WEVENT_NAME_LEN + 1) * WIPS_EID_MAX);

	if(node->alert == 0)
		return 0;

	for(i=WIPS_EID_MIN; i<WIPS_EID_MAX; i++) {
		if(i<WIPS_EID_INFO_GRP && test_wevent_bitmap(i, &node->alert) > 0) {
			get_wevent_name(i);
			if(wevent_name != NULL) {

//printf("get wevent id:%d--times:%d",i, first);

				if(first == 0) {
					sprintf(&wevent_buf[0], "%s", wevent_name);
					len = strlen(wevent_name);
					wevent_buf[len] = '\0';
				}
				else {
					sprintf(&wevent_buf[len], ";%s", wevent_name);
					len += strlen(wevent_name) + 1;
					wevent_buf[len] = '\0';
				}

				first++;
				free(wevent_name);
				wevent_name = NULL;
			}

		}
	}

	return 0;
}

int get_sonar_data_by_wnode(struct w_node *node)
{
	int i, first = 0, len = 0;
    int pri = PRI_GREEN;    /* 0:green, 1:yellow, 2:red*/

	memset(&wevent_buf[0], 0, (WEVENT_NAME_LEN + 1) * WIPS_EID_MAX);

	if(node->alert == 0)
		return 0;

	for(i=WIPS_EID_MIN; i<WIPS_EID_MAX; i++) {
		if(i<WIPS_EID_INFO_GRP && test_wevent_bitmap(i, &node->alert) > 0) {
			get_wevent_name(i);
            get_wevent_pri(i);
            if(wevent_pri != NULL){
                if(strcmp(wevent_pri, "高") == 0) {
                    pri = PRI_RED;
                }
                else if(strcmp(wevent_pri, "中") == 0 && pri < PRI_YELLOW) {
                    pri = PRI_YELLOW;
                }

                free(wevent_pri);
				wevent_pri = NULL;
            }

			if(wevent_name != NULL) {

//printf("get wevent id:%d--times:%d",i, first);

				if(first == 0) {
					sprintf(&wevent_buf[0], "%s", wevent_name);
					len = strlen(wevent_name);
					wevent_buf[len] = '\0';
				}
				else {
					sprintf(&wevent_buf[len], ";%s", wevent_name);
					len += strlen(wevent_name) + 1;
					wevent_buf[len] = '\0';
				}

				first++;
				free(wevent_name);
				wevent_name = NULL;
			}

		}
	}

	return pri;
}

int cb_get_wevent_name(void* data, int n_columns, char** column_values, char** column_names)
{
	if(wevent_name != NULL) {
		free(wevent_name);
		wevent_name = NULL;
	}

	wevent_name = malloc(WEVENT_NAME_LEN);
	if(!wevent_name) {
		return 0;
	}

	memset(wevent_name, 0, WEVENT_NAME_LEN);
	if(column_values[0])
		strncpy(wevent_name, column_values[0], WEVENT_NAME_LEN_L);

	return 0;
}

int get_wevent_name(int weid)
{
	int ret;
	sqlite3 *sql = NULL;
	char query[256];

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		printf("open sqlite wconfig.db error !");
		return 0;
	}

	sprintf(query,"select name from wevent where id=\"%d\"", weid);
	sqlite3_exec(sql, query, cb_get_wevent_name, NULL,NULL);

    if(sql)
    	sqlite3_close(sql);
	return 0;
}

int cb_get_wevent_pri(void* data, int n_columns, char** column_values, char** column_names)
{
	if(wevent_pri != NULL) {
		free(wevent_pri);
		wevent_pri = NULL;
	}

	wevent_pri = malloc(32);
	if(!wevent_pri) {
		return 0;
	}

	memset(wevent_pri, 0, 32);
	if(column_values[0])
		strncpy(wevent_pri, column_values[0], 31);

	return 0;
}

int get_wevent_pri(int weid)
{
	int ret;
	sqlite3 *sql = NULL;
	char query[256];

	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql);
	if(ret != SQLITE_OK){
		printf("open sqlite wconfig.db error !");
		return 0;
	}

	sprintf(query,"select pri from wevent where id=\"%d\"", weid);
	sqlite3_exec(sql, query, cb_get_wevent_pri, NULL,NULL);

    if(sql)
    	sqlite3_close(sql);
	return 0;
}

char *time2string(time_t time1, char **szTime)
{
	struct tm tm1;
	char *buf;

	*szTime = NULL;
	if(time1 <= 0)
		return NULL;

	localtime_r(&time1, &tm1 );

	buf = malloc(32);
	memset(buf, 0, 32);

	sprintf( buf, "%04d-%02d-%02d %02d:%02d:%02d",
			  tm1.tm_year+1900, tm1.tm_mon+1, tm1.tm_mday,
				  tm1.tm_hour, tm1.tm_min,tm1.tm_sec);

	*szTime = buf;
	return buf;
}

short convert_ap_channel(short channel)
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

short reverse_ap_channel(int channel)
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
			return 0;
	}

	return 0;
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

char *convert_sta_rate(short rate)
{

	switch(rate) {

		case 0:
			return "auto";
		case 2:   /*	1 Mb  */
			return "1 Mb";
		case 4:   /*	2 Mb  */
			return "2 Mb";
		case 11:  /*  5.5 Mb  */
			return "5.5 Mb";
		case 12:  /*	6 Mb  */
			return "6 Mb";
		case 13:  /*  6.5 Mb  */
			return "6.5 Mb";
		case 18:  /*	9 Mb  */
			return "9 Mb";
		case 22:  /*   11 Mb  */
			return "11 Mb";
		case 24:  /*   12 Mb  */
			return "12 Mb";
		case 26:  /*   13 Mb  */
			return "13 Mb";
		case 27:  /* 13.5 Mb  */
			return "13.5 Mb";
		case 36:  /*   18 Mb  */
			return "18 Mb";
		case 39:  /* 19.5 Mb  */
			return "19.5 Mb";
		case 48:  /*   24 Mb  */
			return "24 Mb";
		case 52:  /*   26 Mb  */
			return "26 Mb";
		case 54:  /* 27.0 Mb  */
			return "27 Mb";
		case 72:  /*   36 Mb  */
			return "36 Mb";
		case 78:  /*   39 Mb  */
			return "39 Mb";
		case 81:  /* 40.5 Mb  */
			return "40.5 Mb";
		case 96:  /*   48 Mb  */
			return "48 Mb";
		case 104: /*   52 Mb  */
			return "52 Mb";
		case 108: /*   54 Mb  */
			return "54 Mb";
		case 117: /* 58.5 Mb  */
			return "58.5 Mb";
		case 130: /*   65 Mb  */
			return "65 Mb";
		case 156: /*   78 Mb  */
			return "78 Mb";
		case 162: /*   81 Mb  */
			return "81 Mb";
		case 208: /*  104 Mb  */
			return "104 Mb";
		case 216: /*  108 Mb  */
			return "108 Mb";
		case 234: /*  117 Mb  */
			return "117 Mb";
		case 243: /* 121.5Mb  */
			return "121.5 Mb";
		case 260: /*  130 Mb  */
			return "130 Mb";
		case 270: /*  135 Mb  */
			return "135 Mb";
		case 300: /*  150 Mb  */
			return "150 Mb";
		case 324: /*  162 Mb  */
			return "162 Mb";
		case 432: /*  216 Mb  */
			return "216 Mb";
		case 486: /*  243 Mb  */
			return "243 Mb";
		case 540: /*  270 Mb  */
			return "270 Mb";
		case 600: /*  300 Mb  */
			return "300 Mb";

		default:
			return "Unknown";
	}

	return "Unknown";
}


char *get_wips_data(char *type)
{
	int cfd,len;
	int recv_again_num=0;
	struct sockaddr_un un;
	char *buf;
	char cmd[256];
	struct timeval recv_timeval;
	int max=MAX;

	recv_timeval.tv_sec = 2;
	recv_timeval.tv_usec =0;

	if(!type)
		return NULL;

	if((strncmp(type, "aplist", 6)!=0)
		&& (strncmp(type, "stalist", 7)!=0)
		&& (strncmp(type, "wnode", 5)!=0)
		&& (strncmp(type, "print_bt", 8)!=0)
		&& (strncmp(type, "attack", 6)!=0)
		&& (strncmp(type, "TREE_GET_ALL_ESSID",18)!=0)
		&& (strncmp(type, "update_policy", 13)!=0)) {
		printf("get_wips_data command type error!\n");
		printf("type:\naplist, stalist, wnode, update_policy\n");
		return NULL;
	}
#ifdef MIPS	
	if(strncmp(type, "attack", 6)==0){
	  max = EVENT_MEM_LOGGER_NODESIZE * EVENT_MEM_LOGGER_BUFFERSIZE + sizeof(int) + MAX_SHARE_PKT_SIZE;
	}
#endif	
	strncpy(cmd, type, 255);
	cmd[255] = '\0';

	buf = malloc(max);
	if(!buf ) {
		return NULL;
	}
get_wips_data_again:
	memset(buf, 0 , max);

	if((cfd=socket(AF_UNIX,SOCK_STREAM,0))==-1){
		perror("Fail to socket");
		free(buf);
		return NULL;
	}
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeval, sizeof(recv_timeval));

	memset(&un,0,sizeof(struct sockaddr_un));
	un.sun_family=AF_UNIX;
	sprintf(un.sun_path,"%s%d",C_PATH,getpid());
	len=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	unlink(un.sun_path);

	if(bind(cfd,(struct sockaddr *)&un,len)==-1){
		perror("Fail to bind");
		free(buf);
		return NULL;
	}

	if(chmod(un.sun_path,S_IRWXU)<0){
		perror("Fail to chmod");
		free(buf);
		return NULL;
	}

	memset(&un,0,sizeof(struct sockaddr_un));
	un.sun_family=AF_UNIX;
	strcpy(un.sun_path,PATH);

	len=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	if(connect(cfd,(struct sockaddr *)&un,len)<0){
		perror("Fail to connect\n");
		free(buf);
		return NULL;
	}

	if(write(cfd,cmd,256)==-1){
		perror("<!-- Fail to write cmd -->\n");
		free(buf);
		return NULL;
	}

//============================================
{
	char recvnum=0, *recv_bufname, i, recv_head[20];
	int ret;
	if((ret = read( cfd, recv_head, 20))==-1){
		perror("<!-- Fail to read 001 -->\n");
		free(buf);
		//printf("<!-- get data from wips timeout -->\n");
		return NULL;
	}else if(memcmp( recv_head,"send_start",10) == 0){
		if(recv_head[10] > 0 ) recvnum = recv_head[10];
	}else if(recv_again_num < 3){
		close(cfd);
		recv_again_num++;
		goto get_wips_data_again;
	}else{
		free(buf);
		close(cfd);
		return NULL;
	}
	if(write(cfd,"ACK",3)==-1){
		perror("<!-- Fail to write ACK -->\n");
		if(recv_again_num < 3){
			close(cfd);
			recv_again_num++;
			goto get_wips_data_again;
		}else{
			free(buf);
			close(cfd);
			return NULL;
		}
	}

	len = 0;
	for(i=0; i < recvnum; i++){
		recv_bufname = buf + len;
		if((ret = read(cfd,recv_bufname,(max - len)))==-1){
			perror("<!-- Fail to read 002 -->\n");
			ret = write(cfd, "recv_err", 9);
			if(recv_again_num < 3){
				close(cfd);
				recv_again_num++;
				goto get_wips_data_again;
			}else{
				free(buf);
				close(cfd);
				return NULL;
			}
		}else if(memcmp( recv_bufname,"send_err",8) == 0){
			if(recv_again_num < 3){
				close(cfd);
				recv_again_num++;
				goto get_wips_data_again;
			}else{
				free(buf);
				close(cfd);
				return NULL;
			}
		}else if(write(cfd,"ACK",3)==-1){
			if(recv_again_num < 3){
				close(cfd);
				recv_again_num++;
				goto get_wips_data_again;
			}else{
				free(buf);
				close(cfd);
				return NULL;
			}
		}
		len += ret;
	}

	//printf("w_node_len[%d]\n",sizeof(struct w_node));
	if(len < (*((int *)buf) + 4)) {
		if(recv_again_num < 3){
			close(cfd);
			recv_again_num++;
			goto get_wips_data_again;
		}else{
			free(buf);
			close(cfd);
			return NULL;
		}
	}
}
//============================================
	close(cfd);
	return buf;
}

int serialize_wireless_tree(char *ap_list, char *sta_list, int ap_num, int sta_num)
{
	int i,j;
	struct w_node *ap, *sta, *tmp;

	in_ap_num	= 0;
	ex_ap_num	= 0;
	in_sta_num	= 0;
	ex_sta_num	= 0;
	al_sta_num	= 0;

	for(i=0; i<ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));

		if(ap->ipv4[0] != '\0')
			in_ap_num++;
		else
			ex_ap_num++;

		ap->sta_num=0;
		for(j=0; j<sta_num; j++) {
			sta = (struct w_node *)(sta_list + sizeof(int) + j*sizeof(struct w_node));

			if(memcmp(ap->mac, sta->bssid, 6) == 0) {
				sta->psta=NULL;
				ap->sta_num++;
				sta->pap = ap;

				if(ap->ipv4[0] != '\0')
					in_sta_num++;
				else
					ex_sta_num++;

				if(ap->psta == NULL)
					ap->psta = sta;
				else {
					tmp = ap->psta;
					while(tmp->psta) {
						tmp = tmp->psta;
					}
					if(!tmp->psta)
						tmp->psta = sta;
				}
			}

		}
	}

	al_sta_num = all_sta_num - in_sta_num - ex_sta_num;
	return 0;
}

int search_stat_ssid(struct w_ssid ssid_list[], struct w_node *ap)
{
	int i;

	get_stats_ssid(ap);
	if(stats_ssid[0] == '\0') {
		sprintf(stats_ssid, "HidingSSID");
	}

	for(i=0; i<SSID_MAX_NUM; i++) {
		if(ssid_list[i].ssid[0] == '\0') {
			return -1;
		}

		if(strncmp(stats_ssid, ssid_list[i].ssid , SSID_BUFSIZE_D) == 0) {
		    	if(ssid_list[i].type == 1 && ap->ipv4[0] != '\0') {
				return i;
		        }
			else if(ssid_list[i].type == 2 && ap->ipv4[0] == '\0') {
				return i;
			}
		}

	}

	return -1;
}

int add_stat_ssid(struct w_ssid ssid_list[], struct w_node *ap)
{
    int i;

    get_stats_ssid(ap);
    if(stats_ssid[0] == '\0')
        sprintf(stats_ssid, "HidingSSID");

    for(i=0; i<SSID_MAX_NUM; i++) {
        if(ssid_list[i].ssid[0] != '\0')
            continue;

        strncpy(&ssid_list[i].ssid[0],stats_ssid, SSID_BUFSIZE_D-1);

        if(ap->ipv4[0] == '\0') {
            ex_ssid_num++;
            ssid_list[i].type = 2;
        }
        else {
            in_ssid_num++;
            ssid_list[i].type = 1;
        }

        ssid_list[i].pap = ap;
        return i;
    }

    return -1;
}

int add_stat_ap(struct w_ssid ssid_list[], int index, struct w_node *ap)
{
    struct w_node *pap = ssid_list[index].pap;

    if(ssid_list[index].pap == NULL) {
        ssid_list[index].pap = ap;
        return 0;
    }

    while(pap != NULL) {
        if(pap->pap == NULL){
            pap->pap = ap;
            return 0;
        }
        pap = pap->pap;
    }

    return -1;
}


int serialize_wireless_ssid(struct w_ssid inter_ssid_list[], struct w_ssid exter_ssid_list[], char *ap_list, char *sta_list, int ap_num, int sta_num)
{
	int i, j, index, is_inter;
	struct w_node *ap, *sta, *tmp;

	in_ap_num	= 0;
	ex_ap_num	= 0;
	in_sta_num	= 0;
	ex_sta_num	= 0;
	al_sta_num	= 0;

	in_ssid_num = 0;
	ex_ssid_num = 0;

	for(i=0; i<ap_num; i++) { 
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
		ap->pap=NULL;
		ap->sta_num=0;
		ap->psta=NULL;

		if(ap->ipv4[0] != '\0') {
			in_ap_num++;
			is_inter = 1;
			index = search_stat_ssid(inter_ssid_list, ap);

			if(index >= 0)
				add_stat_ap(inter_ssid_list, index, ap);
			else
				add_stat_ssid(inter_ssid_list, ap);

		}
		else {
			ex_ap_num++;
			is_inter = 0;
			index = search_stat_ssid(exter_ssid_list, ap);

			if(index >= 0)
				add_stat_ap(exter_ssid_list, index, ap);
			else
				add_stat_ssid(exter_ssid_list, ap);
		}


		for(j=0; j<sta_num; j++) {
			sta = (struct w_node *)(sta_list + sizeof(int) + j*sizeof(struct w_node));	
			if(memcmp(ap->mac, sta->bssid, 6) == 0) {
				sta->psta=NULL;
				ap->sta_num++;
				sta->pap = ap;

				if(ap->ipv4[0] != '\0')
					in_sta_num++;
				else
					ex_sta_num++;

				if(ap->psta == NULL)
					ap->psta = sta;
				else {
					tmp = ap->psta;
					while(tmp->psta) {
						tmp = tmp->psta;
					}
					tmp->psta = sta;
				}
			}

		}
	}

	al_sta_num = all_sta_num - in_sta_num - ex_sta_num;
	return 0;
}

int whandle_sql_get_wips_log(void* data, int n_columns, char** column_values, char** column_names)
{
	char permit[8], pri[8];
	char ssid_tmp[SSID_BUFSIZE_D];
	wips_log_num++;

    if(wips_log_num < start)
        return 0;
    else if(wips_log_num > (start + limit))
        return 0;
    else if(wips_log_num > total)
        return 0;

	if(strncmp(column_values[6], "1", 1) == 0)
		sprintf(permit, "是");
	else
		sprintf(permit, "否");

	if(column_values[7])
		strcpy(pri, column_values[7]);
	else
		strcpy(pri, " ");

	if(wips_log_num > start+1)
		printf(",\n");
	
	strcpy(ssid_tmp, column_values[14]);
	printf("{ID:%d, mac:\"%s\", bssid:\"%s\", ssid:\"%s\", name:\"%s\", "
	       "channel:\"%s\", alert:\"%s\", permit:\"%s\","
	       "pri:\"%s\", time:\"%s\"}",
	       wips_log_num, column_values[1], column_values[0], deal_ssid(ssid_tmp), column_values[13],
	       column_values[2], column_values[5], permit, pri, column_values[8]);


	return 0;
}

#ifdef MIPS
int init_wips_data(struct event_memlog_pkt** ppkt, int* pktnum, wevent_struct** pwevent_list)
{
	char* pkt = get_wips_data("attack_list");
	int nodenum = 0;
	wevent_struct* wevent_list_local = NULL;
	
	if(pkt!=NULL){
		nodenum  = ((*(int*)pkt)-sizeof(int))/EVENT_MEM_LOGGER_NODESIZE;
		struct attack_share_pkt* aspkt = (struct attack_share_pkt*)(pkt+sizeof(int)+nodenum*EVENT_MEM_LOGGER_NODESIZE);
		int wevent_listid = aspkt->wevent_key;
		wevent_num = aspkt->wevent_kindnum;
		wevent_grp_num = aspkt->wevent_grpnum;
		if(wevent_listid!=0) {
			int i=0;
			do{
				wevent_list_local = (wevent_struct*)shmat(wevent_listid, 0, SHM_RDONLY);
			}while(++i<50 && wevent_list_local==(void*)-1);

			if(wevent_list_local==(void*)-1){
				wevent_list_local = NULL;
			}
		}
	}
	
	*ppkt = (struct event_memlog_pkt*)(pkt+sizeof(int));
	*pktnum = nodenum;
	*pwevent_list = wevent_list_local;
	
	return pkt!=NULL && wevent_list_local!=NULL;
}

void destroy_wips_data(struct event_memlog_pkt* pkt, wevent_struct* wevent_list_local)
{
	if(wevent_list_local!=NULL) {
		shmdt(wevent_list_local);
	}  
	if(pkt!=NULL){
		free((char*)pkt-sizeof(int));
	}
}

int wips_attack_list(void)
{
#define GEN_TIMESTR_BY_TIMEVAL(stimeval, timestrname) \
  char timestrname[100]; \
  {  struct tm* localtm=localtime(&(stimeval.tv_sec));	     \
     sprintf(timestrname, "%d-%02d-%02d %02d:%02d:%02d.%06ld",  \
     localtm->tm_year+1900, localtm->tm_mon+1, localtm->tm_mday, \
     localtm->tm_hour, localtm->tm_min, localtm->tm_sec, stimeval.tv_usec);}
#define GEN_MAC_BY_ARRAY(macbuffer, intof6) sprintf(macbuffer, "%02x:%02x:%02x:%02x:%02x:%02x", (int)(intof6[0]), (int)(intof6[1]), (int)(intof6[2]), (int)(intof6[3]), (int)(intof6[4]), (int)(intof6[5]))

	int nodenum = 0;
	struct event_memlog_pkt* mpkt = NULL;
	wevent_struct* wevent_list_share = NULL;
	init_wips_data(&mpkt, &nodenum, &wevent_list_share);
	struct event_memlog_pkt* mpkt_newest = mpkt!=NULL ? mpkt + nodenum -1 : NULL;	
	/*
	if(mpkt!=NULL && wevent_list_share!=NULL){
		int i;
		for(i=0; i<WIPS_EID_MAX; i++){
		  printf("EID: %d\tNAME:%s\n", i, wevent_list_share[i].name);
		}
	}*/
	if(mpkt!=NULL){
		if(topN>0) {
		limit = topN;
		nodenum = topN;
		}
		printf("{success:true, total:%d, data:[\n", nodenum);
		int i;
		
		for(i=start; i<start+limit && i<nodenum; i++){
			struct event_memlog_pkt* ppkt = mpkt_newest - i;
			int event = ppkt->type;
			char mac[24];
			char setid[sizeof(ppkt->val.ssid)>sizeof(mac)?sizeof(ppkt->val.ssid):sizeof(mac)];
			
			GEN_MAC_BY_ARRAY(mac, ppkt->val.mac);
			if((ppkt->val.node_type & 0x01)==0x01){
			  memcpy(setid, ppkt->val.ssid, sizeof(ppkt->val.ssid));
			}else if((ppkt->val.node_type & 0x06)){
				GEN_MAC_BY_ARRAY(setid, ppkt->val.bssid);
			}else{
				continue;
			}
			
			GEN_TIMESTR_BY_TIMEVAL(ppkt->when_event_happen, detect_time);
			if( event < WIPS_EID_MAX ){
				printf("{ID:%d, mac:\"%s\", bssid:\"%s\", "
				"channel:\"%d\", alert:\"%s\", permit:\"%s\","
				"pri:\"%s\", time:\"%s\"}", i+1, mac, setid, (int)(ppkt->val.channel), wevent_list_share==NULL?"未定义":wevent_list_share[event-1].name, ppkt->val.block==1?"是":"否", wevent_list_share==NULL?"未定义":wevent_list_share[event-1].pri, detect_time);
			}else if( event > WIPS_EID_MAX ){
				printf("{ID:%d, mac:\"%s\", bssid:\"%s\", "
				"channel:\"%d\", alert:\"%s\", permit:\"%s\","
				"pri:\"%s\", time:\"%s\"}", i+1, mac, setid, (int)(ppkt->val.channel), eve_pri_table[event-1].name, ppkt->val.block==1?"是":"否", "提示", detect_time);
			}
			
			if(i<nodenum-1 && i<start+limit-1) 
				printf(",");
		}
		printf("]}\n");
	}

       destroy_wips_data(mpkt, wevent_list_share);
       return 0;
 }

void wips_attack_traverse_wevent(void(*traversefunc)(char* ,int))
{
	int i = 0;
	int nodenum = 0;
	struct event_memlog_pkt* mpkt = NULL;
	wevent_struct* wevent_list_share = NULL;
	do {
		init_wips_data(&mpkt, &nodenum, &wevent_list_share);
	}while( ++i<50 && (mpkt==NULL || wevent_list_share==NULL) );
	if(mpkt==NULL || wevent_list_share==NULL)
		return;

	int* eventcount = (int*)calloc(wevent_num, sizeof(int));
	for(i=0; i<nodenum; i++){
		++eventcount[mpkt[i].type - WIPS_EID_MIN];
		++eventcount[wevent_list_share[mpkt[i].type-1].grp_id - WIPS_EID_MIN];
	}

	for (i = WIPS_EID_MIN+1; i < wevent_num + WIPS_EID_MIN; i++) {
		if(wevent_list_share[i-1].is_grp == 1) {
			DR(0, 2, "NAME:%s\t COUNT:%d", wevent_list_share[i-1].name, eventcount[i-WIPS_EID_MIN] );
			traversefunc(	wevent_list_share[i-1].name, eventcount[i-WIPS_EID_MIN] );
		}
	}  
	DR(0, 2, "CUR LOG SUCCESS-----");
	free(eventcount);
	destroy_wips_data(mpkt, wevent_list_share);
}

void wips_attack_print_with_text(char* name, int value)
{printf("<set name='%s' value='%d' tooltext='%s\n数量 %d'/>\n",name==NULL?"NULL":name, value, name==NULL?"NULL":name, value);}

void wips_attack_print_no_text(char* name, int value)
{printf("<set name='%s' value='%d'/>\n",name==NULL?"NULL":name, value);}

int wips_attack_column_cur(void)
{	
	printf("<graph caption='最近发生的无线事件' animation ='0' showShadow='0' "
		"plotFillRatio='100' bgColor='E7F0F9' showBorder='0'");
	printf("decimalPrecision=\"2\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"outCnvBaseFontSize=\"12\" yAxisName=\"num\"");
	printf("useRoundEdges='1' showAreaBorder='0' areaAlpha='100' numVDivLines='20' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBgColor='E7F0F9' canvasBorderColor='cccccc' canvasBorderThickness='1' >\n");
	printf_style();
	wips_attack_traverse_wevent(wips_attack_print_with_text);
	printf("</graph>\n");
	return 0;
}

int wips_attack_column_total(void)
{

	printf("<graph caption='累计无线事件' animation ='0' showShadow='0' "
		"plotFillRatio='100' bgColor='E7F0F9' showBorder='0'");
	printf("decimalPrecision=\"2\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"outCnvBaseFontSize=\"12\" yAxisName=\"num\"");
	printf("useRoundEdges='1' showAreaBorder='0' areaAlpha='100' numVDivLines='20' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBgColor='E7F0F9' canvasBorderColor='E7F0F9' canvasBorderThickness='1' >\n");
	printf_style();
	wips_attack_traverse_wevent(wips_attack_print_with_text);
	printf("</graph>\n");
	return 0;
}


int wips_attack_pie_cur(void)
{
	printf("<chart caption='最近24小时无线事件分布' animation ='0' showBorder='0' decimalPrecision=\"1\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"bgColor=\"E7F0F9\" outCnvBaseFont=\"Arial\" outCnvBaseFontSize=\"12\">\n");
	wips_attack_traverse_wevent(wips_attack_print_no_text);
	printf("</chart>\n");
	return 0;
}

int wips_attack_pie_total(void)
{
	printf("<chart caption='无线事件累计分布' animation ='0' showBorder='0' decimalPrecision=\"1\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"bgColor=\"E7F0F9\" outCnvBaseFont=\"Arial\" outCnvBaseFontSize=\"12\">\n");
	wips_attack_traverse_wevent(wips_attack_print_no_text);
	printf("</chart>\n");
	return 0;
}


int wips_attack_funnel_total(void)
{
	printf("<chart caption='无线事件累计分布' isSliced='0' showBorder='0' streamlinedData='0' isHollow='0' baseFontSize='12' bgColor=\"E7F0F9\" >\n");
	wips_attack_traverse_wevent(wips_attack_print_no_text);
	printf("</chart>\n");
	return 0;
}
#else
int wips_attack_list(void)
{
	sqlite3 *sql_wips_log = NULL;
	int ret, row=0,col=0,num;
	char **dbResult;
	char *errmsg;
	char query[256];

	ret = sqlite3_open("/usr/hls/log/log/wips_log.db",&sql_wips_log);

	if(ret != SQLITE_OK) {
		printf("open sqlite table wips_log.db failed!");
		return ret;
	}
	
	int trytimes = 0;
	do{
	  ret = sqlite3_get_row( sql_wips_log, "select * from wips_event", &dbResult, &row, &col, &errmsg);
	}while(row==0 && ++trytimes < 100000);

	if(row > 6000) {
        num = row - 5000;
        sprintf(query, "delete from wips_event where rowid in (select rowid from wips_event order by up_time asc limit %d)", num);
        sqlite3_exec(sql_wips_log, query, NULL, NULL , NULL);
        sqlite3_exec(sql_wips_log, "VACUUM", NULL, NULL , NULL);
		row = row - num;
	}

	total = num = topN? min(row, topN):row;
	printf("{success:true, total:%d, data:[\n", num);

	wips_log_num = start;
	sprintf(query, "select * from wips_event order by up_time desc limit %d offset %d", num, start);
	ret = sqlite3_exec(sql_wips_log, query, whandle_sql_get_wips_log, NULL , NULL);

	printf("]}\n");

    if(sql_wips_log)
    	sqlite3_close(sql_wips_log);

	return 0;
}

int whandle_sql_wips_calc(void* data, int n_columns, char** column_values, char** column_names)
{
	int i;

	for( i=0; i < wevent_num; i++ ) {
		if(column_values[9] == NULL)
			continue;

		if(wevent_list[i].id == atoi(column_values[9])) {
			wevent_list[i].count++;
			wevent_list[wevent_list[i].grp_id-1].count++;
		}
	}


	return 0;
}

int wips_attack_calc_day(void)
{
	sqlite3 *sql_wips_log = NULL;
	int ret;
	char query[256];

	init_wevent_list();

	ret = sqlite3_open("/usr/hls/log/log/wips_log.db",&sql_wips_log);

	if(ret != SQLITE_OK) {
		printf("open sqlite table wips_log.db failed!");
		return ret;
	}

//	sprintf(query, "select * from wips_event order by up_time desc limit 30");
    sprintf(query, "select * from wips_event where up_time > datetime('now', '-1 day')");

	ret = sqlite3_exec(sql_wips_log, query, whandle_sql_wips_calc, NULL , NULL);

    if(sql_wips_log)
    	sqlite3_close(sql_wips_log);

	return 0;
}

int wips_attack_calc_total(void)
{
	sqlite3 *sql_wips_log = NULL;
	int ret;
	char query[256];

	init_wevent_list();

	ret = sqlite3_open("/usr/hls/log/log/wips_log.db",&sql_wips_log);

	if(ret != SQLITE_OK) {
		printf("open sqlite table wips_log.db failed!");
		return ret;
	}

	sprintf(query, "select * from wips_event");
	ret = sqlite3_exec(sql_wips_log, query, whandle_sql_wips_calc, NULL , NULL);

    if(sql_wips_log)
    	sqlite3_close(sql_wips_log);

	return 0;
}


int wips_attack_column_cur(void)
{
	int i;

	wips_attack_calc_day();

	printf("<graph caption='最近24小时无线事件' animation ='0' showShadow='0' "
		"plotFillRatio='100' bgColor='E7F0F9' showBorder='0'");
	printf("decimalPrecision=\"2\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"outCnvBaseFontSize=\"12\" yAxisName=\"num\"");

	printf("useRoundEdges='1' showAreaBorder='0' areaAlpha='100' numVDivLines='20' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBgColor='E7F0F9' canvasBorderColor='cccccc' canvasBorderThickness='1' >\n");


	printf_style();

	for (i = 0; i < wevent_num; i++) {
		if(wevent_list[i].is_grp == 1 && wevent_list[i].id != 1) {
			printf("<set name='%s' value='%d' tooltext='%s\n数量 %d'/>\n",
				wevent_list[i].name, wevent_list[i].count, wevent_list[i].name, wevent_list[i].count);
		}
	}

	printf("</graph>\n");

	destory_wevent_list();

	return 0;
}

int wips_attack_column_total(void)
{
	int i;

	wips_attack_calc_total();

	printf("<graph caption='累计无线事件' animation ='0' showShadow='0' "
		"plotFillRatio='100' bgColor='E7F0F9' showBorder='0'");
	printf("decimalPrecision=\"2\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"outCnvBaseFontSize=\"12\" yAxisName=\"num\"");

	printf("useRoundEdges='1' showAreaBorder='0' areaAlpha='100' numVDivLines='20' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBgColor='E7F0F9' canvasBorderColor='E7F0F9' canvasBorderThickness='1' >\n");


	printf_style();

	for (i = 0; i < wevent_num; i++) {
		if(wevent_list[i].is_grp == 1 && wevent_list[i].id != 1) {
			printf("<set name='%s' value='%d' tooltext='%s\n数量 %d'/>\n",
				wevent_list[i].name, wevent_list[i].count, wevent_list[i].name, wevent_list[i].count);
		}
	}

	printf("</graph>\n");

	destory_wevent_list();

	return 0;
}


int wips_attack_pie_cur(void)
{
	int i;

	wips_attack_calc_day();

	printf("<chart caption='最近24小时无线事件分布' animation ='0' showBorder='0' decimalPrecision=\"1\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"bgColor=\"E7F0F9\" outCnvBaseFont=\"Arial\" outCnvBaseFontSize=\"12\">\n");

	for (i = 0; i < wevent_num; i++) {
		if(wevent_list[i].is_grp == 1 && wevent_list[i].id != 1) {
			printf("<set label='%s' value='%d'/>\n",
				wevent_list[i].name, wevent_list[i].count);
		}
	}

	printf("</chart>\n");

	destory_wevent_list();

	return 0;
}

int wips_attack_pie_total(void)
{
	int i;

	wips_attack_calc_total();

	printf("<chart caption='无线事件累计分布' animation ='0' showBorder='0' decimalPrecision=\"1\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"bgColor=\"E7F0F9\" outCnvBaseFont=\"Arial\" outCnvBaseFontSize=\"12\">\n");

	for (i = 0; i < wevent_num; i++) {
		if(wevent_list[i].is_grp == 1 && wevent_list[i].id != 1) {
			printf("<set label='%s' value='%d'/>\n",
				wevent_list[i].name, wevent_list[i].count);
		}
	}

	printf("</chart>\n");

	destory_wevent_list();

	return 0;
}

int wips_attack_funnel_total(void)
{
	int i;

	wips_attack_calc_total();

//	printf("<chart caption='无线事件累计分布' isSliced='0' showBorder='0' streamlinedData='0' isHollow='0' numberSuffix='Bytes' baseFontSize='12' bgColor=\"ffffff\" >\n");
	printf("<chart caption='无线事件累计分布' isSliced='0' showBorder='0' streamlinedData='0' isHollow='0' baseFontSize='12' bgColor=\"E7F0F9\" >\n");

	for (i = 0; i < wevent_num; i++) {
		if(wevent_list[i].is_grp == 1 && wevent_list[i].id != 1) {
			printf("<set label='%s' value='%d'/>\n",
				wevent_list[i].name, wevent_list[i].count);
		}
	}

	printf("</chart>\n");

	destory_wevent_list();

	return 0;
}
#endif

int wips_print_block_table()
{
    char *ret;
    ret = get_wips_data("print_bt");

    if(ret != NULL)
        free(ret);

    return 0;
}

int rf_vled_gauge(void)
{
	int i;
	float txpower = 0,dbm;
	struct w_node *ap;
	char *ap_list;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		all_ap_num = 0;
	}
	else {
	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);
	}

	for(i = 0; i < all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
		dbm = (float)ap->signal;
		txpower += pow(10.0, dbm/10.0);
	}

	if(txpower > 0)
		dbm = log10(txpower) * 10.0;
	else
		dbm = -95.0;


	free(ap_list);

//	printf("<chart palette='3' caption='RF Status' bgColor='FFFFFF' autoScale='1' origW='30' showBorder='0' lowerLimit='-110' upperLimit='-10' lowerLimitDisplay='Low' upperLimitDisplay='High' numberSuffix='dbm' chartRightMargin='20' showValue='1'>\n");
	printf("<chart palette='3' caption='RF Status' bgColor='E7F0F9' showToolTip='1' showBorder='0' ticksOnRight='0' lowerLimit='-110' upperLimit='-10' lowerLimitDisplay='Low' upperLimitDisplay='High' numberSuffix='dbm' showValue='1'>\n");
 	printf("<colorRange>\n");
	printf("<color minValue='-110' maxValue='-95' code='FF654F'/>\n");
	printf("<color minValue='-95' maxValue='-80' code='F6BD0F'/>\n");
	printf("<color minValue='-80' maxValue='-10' code='8BBA00'/>\n");
	printf("</colorRange>\n");
	printf("<value>%d</value>", (int)dbm);
	printf("</chart>\n");


	return 0;
}

int print_sonar_element(int id)
{
    printf("null]},\n"
		"{\n"
   		"\"type\":\"area\",\n"
    		"\"colour\":\"#202020\",\n"
    		"\"fill-alpha\":0.1,\n"
    		"\"dot-style\":{\"dot-size\":2,\"halo-size\":2,\"type\":\"solid-dot\"},\n"
    		"\"on-show\":{\"cascade\":0,\"delay\":0,\"type\":\"\"},\n"
    		"\"width\":1,\n"
    		"\"font-size\":10,\n"
    		"\"alpha\":0.1,\n"
    		"\"loop\":true,\n"
    		"\"key-on-click\":\"toggle-visibility\",\n"
		"\"id\":\"chart_element_%d\",\n\"values\":[\n", id);
	return 0;
}

int print_null_point(int num)
{
    int i;

    for(i = 0; i < num; i++) {
        printf("null,");
    }

    return 0;
}

int wips_sonar_scan(void)
{
	int i,pri,y_value,null_num,ele_num;
	struct w_node *ap;
	char *ap_list;
//    char *we;
    char mac[24];

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		all_ap_num = 0;
	}
	else {
    	all_ap_num =  *((int *)(ap_list));
    	all_ap_num = all_ap_num/sizeof(struct w_node);
	}

    printf("{\n"
		"\"title\":{\n"
		"	\"text\":\"\",\n"
		"	\"style\":\"font-size:12px;\n"
		"	color:#777777;\n"
		"	text-align:center;\n"
		"	font-weight:bold;\"\n"
		"},\n"
		"\"x_axis\":{\n"
		"	\"colour\":\"#999999\",\n"
		"	\"grid-colour\":\"#3c3c3c\",\n"
		"	\"stroke\":1,\"\n"
		"	labels\":{\"colour\":\"#777777\"},\n"
		"	\"tick-height\":10\n"
		"},\n"
		"\"y_axis\":{\n"
		"	\"min\":1,\n"
		"	\"colour\":\"#999999\",\n"
		"	\"grid-colour\":\"#3c3c3c\",\n"
		"	\"stroke\":1,\n"
		"	\"max\":20,\n"
		"	\"labels\":{\"colour\":\"#777777\"},\n"
		"	\"tick-length\":5\n"
		"},\n"
		"\"radar_axis\":{\n"
		"	\"min\":0,\"colour\":\"#999999\",\n"
		"	\"grid-colour\":\"#3c3c3c\",\n"
		"	\"stroke\":1,\n"
		"	\"max\":10,\n"
		"	\"labels\":{\"colour\":\"#777777\"},\n"
		"	\"spoke-labels\":{\"colour\":\"#777777\"},\n"
		"	\"steps\":1\n"
		"},\n"
		"\"legend\":{\n"
		"	\"position\":\"right\",\n"
		"	\"stroke\":1,\n"
		"	\"visible\":true,\n"
		"	\"shadow\":false,\n"
		"	\"bg_colour\":\"#313131\",\n"
		"	\"border\":true,\n"
		"	\"border_color\":\"#f0f0f0\"\n"
		"},\n"
		"\"tooltip\":{\n"
		"	\"colour\":\"#ffffff\",\n"
		"	\"body\":\"font-size:10px;colour:#ff0000;\",\n"
		"	\"title\":\"font-size:12px;colour:#00ff00;\",\n"
		"	\"mouse\":\"2\",\n"
		"	\"background\":\"#ffffff\"\n"
		"},\n"
		"\"bg_colour\":\"#E7F0F9\",\n"
		"\"currentTheme\":\"dark\",\n"
		"\"is_decimal_separator_comma\":0,\n"
		"\"is_fixed_num_decimals_forced\":0,\n"
		"\"is_thousand_separator_disabled\":0,\n"
		"\"y_axis_auto_range\":true,\n"
		"\"x_axis_auto_range\":false,\n"
		"\"num_decimals\":2,\n"
		"\"elements\":[\n"
		"	{\n"
		"	\"type\":\"area\",\n"
		"	\"colour\":\"#202020\",\n"
		"	\"fill-alpha\":0.1,\n"
		"	\"dot-style\":{\"dot-size\":2,\"halo-size\":2,\"type\":\"solid-dot\"},\n"
		"	\"on-show\":{\"cascade\":0,\"delay\":0,\"type\":\"\"},\n"
		"	\"width\":1,\n"
		"	\"font-size\":10,\n"
		"	\"alpha\":0.1,\n"
		"	\"loop\":true,\n"
		"	\"key-on-click\":\"toggle-visibility\",\n"
		"	\"id\":\"chart_element_0\",\n"
		"	\"values\":[\n");
	
    y_value = 1;
    null_num = 20;
    ele_num = 4;

	for(i = 0; i < all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));

        pri = get_sonar_data_by_wnode(ap);
        get_stats_ssid(ap);
        deal_ssid((char *)&stats_ssid[0]);

//        we = &wevent_buf[0];
        sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		    ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);

        if(i == 4) {
            print_sonar_element(1);
            y_value = 2;
            null_num = 15;
            ele_num = 6;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }
        else if(i == 10) {
            print_sonar_element(2);
            y_value = 3;
            null_num = 8;
            ele_num = 10;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }
        else if(i == 20) {
            print_sonar_element(3);
            y_value = 4;
            null_num = 4;
            ele_num = 17;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }
        else if(i == 37) {
            print_sonar_element(4);
            y_value = 5;
            null_num = 3;
            ele_num = 21;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }
        else if(i == 58) {
            print_sonar_element(5);
            y_value = 6;
            null_num = 2;
            ele_num = 29;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }
        else if(i == 87) {
            print_sonar_element(6);
            y_value = 7;
            null_num = 1;
            ele_num = 44;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }
        else if(i == 131) {
            print_sonar_element(7);
            y_value = 8;
            null_num = 1;
            ele_num = 44;
            if(all_ap_num  < i + ele_num) {
                ele_num = all_ap_num - i;
                null_num = 90/ele_num - 1;
            }
        }


        if(pri == PRI_RED) {
            printf("{\"colour\":\"#ff0000\",\"dot-size\":2,\"value\":%d,\"tip\":\"%s\t%s\"},\n",
                y_value,
                (char *)P(stats_ssid),
                (char *)P(mac));
        }
        else if(pri == PRI_YELLOW) {
            printf("{\"colour\":\"#F6EA05\",\"dot-size\":2,\"value\":%d,\"tip\":\"%s\t%s\"},\n",
                y_value,
                (char *)P(stats_ssid),
                (char *)P(mac));
        }
        else/*(pri == PRI_GREEN)*/ {
            printf("{\"colour\":\"#00ff00\",\"dot-size\":2,\"value\":%d,\"tip\":\"%s\t%s\"},\n",
                y_value,
                (char *)P(stats_ssid),
                (char *)P(mac));
        }

        print_null_point(null_num);
/*        if(first == 0)
            printf(",\"background-alpha\":0},\n");
        else
            printf("},\n");

        first++;*/

	}

	free(ap_list);

/*    printf("		{\"colour\":\"#ff0000\",\"dot-size\":3,\"value\":1,\"tip\":\"7.7.7.14\t2012-01-13 13:44\n\",\"background-alpha\":0},\n");
    printf("		null,\n");
    printf("		{\"colour\":\"#F6EA05\",\"dot-size\":3,\"value\":1,\"tip\":\"7.7.7.16\t2012-01-13 13:19\n\"},\n");
    printf("		null		 		\n");
    printf("		{\"colour\":\"#00ff00\",\"dot-size\":3,\"value\":1,\"tip\":\"7.7.7.15\t2012-01-13 13:19\n\"},\n");
    printf("		null,\n");*/
    printf("	null]\n");
    printf("	}\n");
    printf("]\n");
    printf("}\n");

	return 0;
}


int draw_alone_sta_list(char *sta_list)
{
	int i, par = id_unknown;
	struct w_node *sta;
	char *tm1,*tm2;

	for(i=0; i<all_sta_num; i++) {
		sta = (struct w_node *)(sta_list + sizeof(int) + i*sizeof(struct w_node));

		if(sta->pap)
			continue;

		par = id_unknown;

		if(par <= 0)
			par = parent;

		printf(",\n");

		time2string(sta->up_time, &tm1);
		time2string(sta->last_time,&tm2);

		printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
				sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
				(char *)P(sta->vendor), convert_ap_channel(sta->channel),
				convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
				(char *)P(tm1),(char *)P(tm2), id_index, par);

		free(tm1);
		free(tm2);

		id_index++;

	}

	return 0;
}

int draw_association_sta(struct w_node *ap)
{
	struct w_node *psta;
	int px,py;
	char mac[24];

	psta = ap->psta;

	while(ap->sta_num && psta != NULL) {

//		if(sta_column_num > 16)		//最多画16个STA
//			return 0;
		
		if(sta_column_num >= 8) {
			px = sta_px + ((sta_column_num - 8) * sta_step_x);
			py = sta_py - sta_step_y;
		}
		else {
			px = sta_px + (sta_column_num * sta_step_x);
			py = sta_py;
		}


//		psta->sta_num = 254;		//tagged for station has drawwing
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			psta->mac[0],psta->mac[1],psta->mac[2],psta->mac[3],psta->mac[4],psta->mac[5]);

		printf("<set x='%d' y='%d' width='%d' height='%d' name='%s' color='FE3233' id='%s' imageNode='1' "
			"imageURL='images/sta.png' alpha='0' imageAlign='MIDDLE' toolText='%s' link=\"JavaScript:viewSta('%s');\"/> \n",
			px,py, STA_PIX_X,STA_PIX_Y, mac, mac, mac, mac);

		sta_column_num++;
		psta = psta->psta;

	}

	return 0;
}

int draw_alone_sta(char *sta_list)
{
	int i,px,py;
	struct w_node *sta;
	char mac[24];

	for(i=0; i<all_sta_num; i++) {
		sta = (struct w_node *)(sta_list + sizeof(int) + i*sizeof(struct w_node));

		if(sta->pap)
			continue;

		sta_py++;
		if(sta_py > sta_column_num || (x_start + sta_step_x*sta_py)>98) {

			y_start += sta_step_y;
			sta_px = 1;
			sta_py = 2;
		}

		px = x_start + sta_step_x*sta_py;
		py = y_start + sta_step_y*sta_px;

//fprintf(msg, " stax=%d stay=%d, ",px,py);
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5]);

		printf("<set x='%d' y='%d' width='%d' height='%d' name='%s' color='FE3233' id='%s' imageNode='1' "
			"imageURL='images/sta.png' alpha='0' imageAlign='MIDDLE' toolText='%s' link=\"JavaScript:viewSta('%s');\"/> \n",
			px,py, STA_PIX_X,STA_PIX_Y, mac, mac, mac, mac);

	}

	return 0;
}


int draw_inter_ap_connector(char *ap_list)
{
	int i;
	struct w_node *ap;
	char mac[24];

	for(i=0; i<all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
		if(ap->ipv4[0] == '\0')
			continue;

		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);
		printf("<connector strength='0.3' from='%s' to='wips' color='BBBB00' arrowAtStart='0' arrowAtEnd='0' /> \n", mac);
	}
	return 0;
}

int draw_sta_connector(char *sta_list)
{
	int i;
	struct w_node *sta;
	char mac[24],bssid[24];

	for(i=0; i<all_sta_num; i++) {
		sta = (struct w_node *)(sta_list + sizeof(int) + i*sizeof(struct w_node));

		if(sta->pap == NULL /*|| sta->sta_num != 254*/)
			continue;

		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5]);
		sprintf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x",
			sta->bssid[0],sta->bssid[1],sta->bssid[2],sta->bssid[3],sta->bssid[4],sta->bssid[5]);

		if(sta->block == 0)
			printf("<connector strength='0.1' from='%s' to='%s' color='BBBB00' arrowAtStart='0' arrowAtEnd='0' /> \n",
				mac, bssid);
		else
			printf("<connector strength='0.5' from='%s' to='%s' color='F20707' arrowAtStart='0' arrowAtEnd='0' /> \n",
				mac, bssid);
	}
	return 0;
}


int wips_draw_scatter_by_channel(char *ap_list, short channel, int mode)
{
	int i;
	struct w_node *ap;
	char mac[24];
	short ch;
	srand(time(NULL));
	for(i=0; i<all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
/*
	if(ap->channel > 2000)
		ch = reverse_ap_channel(channel);
*/
	if(mode == 2){
		ch = channel;
	}
	else ch = channel_5g[channel];

		if(ap->channel == ch && mode == ap->freq_band) {

			sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);

			get_stats_ssid(ap);
			deal_ssid((char *)&stats_ssid[0]);
			printf("<set id='%s' x='%f' y='%d' tooltext='%s\n%s\n%s\nCH%d'/> \n",
				mac,
				0-(ap->signal+rand()/(double)(RAND_MAX)-0.5),   //add +-0.5 random disturbance
				ch,
				(char *)P(stats_ssid),
				mac,
				(char *)P(ap->ipv4),
				ch);
		}
	}

	return 0;
}

int wips_get_wireless_list(void)
{
	int i,k,par;
	char *ap_list, *sta_list;
	struct w_node *ap, *sta;
	char *tm1, *tm2;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);


	sta_list = get_wips_data("stalist");
	if(sta_list == NULL) {
		free(ap_list);
		return 0;
	}

	all_sta_num =  *((int *)(sta_list));
	all_sta_num = all_sta_num/sizeof(struct w_node);

	serialize_wireless_tree(ap_list, sta_list, all_ap_num, all_sta_num);


	printf("{\"data\":[");

	id_index = 3;
	k = 0;

	for(i=0; i<in_ap_num; i++) {
		if(i == 0) {
			parent = 1;
			printf("{\"name\":\"Internal\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":1, \"_parent\":0, \"_level\":1, \"_is_leaf\":false},\n");
		}
		else
			printf(",\n");

		ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
		while(ap->ipv4[0] == '\0') {
			k++;
			if(k >= all_ap_num)
				goto inter_ap_end;
			ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
		}

		get_stats_ssid(ap);
		deal_ssid((char *)&stats_ssid[0]);
		printf("{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":1, \"_level\":2, \"_is_leaf\":false},\n",
			(char *)P(stats_ssid), id_index);

		parent = id_index;
		id_index++;

		time2string(ap->up_time, &tm1);
		time2string(ap->last_time,&tm2);

		printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
				(char *)P(ap->ipv4), (char *)P(ap->vendor), convert_ap_channel(ap->channel),
				convert_ap_mode(ap->g_rates, ap->n_rates),(char *)P(ap->sec_type),
				ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2),
				id_index, parent, ap->sta_num>0?"false":"true");

		free(tm1);
		free(tm2);

		ap->id = id_index;
		parent = id_index;
		id_index++;
		id_unknown = 0;

		sta = ap->psta;

		while(ap->sta_num && sta != NULL) {

			par = id_unknown;
			if(par <= 0)
				par = parent;

			printf(",\n");

			time2string(sta->up_time, &tm1);
			time2string(sta->last_time,&tm2);

			printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
					sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
					(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
					convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
					(char *)P(tm1),(char *)P(tm2), id_index, par);

			free(tm1);
			free(tm2);

			id_index++;

			sta = sta->psta;

		}

		k++;
		if(k >= all_ap_num) break;

	}

inter_ap_end:

	k = 0;
	for(i=0; i<ex_ap_num; i++) {

		if(i == 0) {
			parent = 1;
			if(in_ap_num > 0)
				printf(",\n");

			printf("{\"name\":\"External\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":2, \"_parent\":0, \"_level\":1, \"_is_leaf\":false},\n");
		}
		else
			printf(",\n");

		ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
		while(ap->ipv4[0] != '\0') {
			k++;
			if(k >= all_ap_num)
				goto exter_ap_end;
			ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
		}

		get_stats_ssid(ap);
		deal_ssid((char *)&stats_ssid[0]);
		printf("{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":false},\n",
			(char *)P(stats_ssid), id_index);

		parent = id_index;
		id_index++;

		time2string(ap->up_time, &tm1);
		time2string(ap->last_time,&tm2);

		printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
				(char *)P(ap->ipv4), (char *)P(ap->vendor), convert_ap_channel(ap->channel),
				convert_ap_mode(ap->g_rates, ap->n_rates), (char *)P(ap->sec_type),
				ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2),
				id_index, parent, ap->sta_num>0?"false":"true");

		free(tm1);
		free(tm2);

		ap->id = id_index;
		parent = id_index;
		id_index++;
		id_unknown = 0;

		sta = ap->psta;

		while(ap->sta_num && sta != NULL) {

			par = id_unknown;
			if(par <= 0)
				par = parent;

			printf(",\n");

			time2string(sta->up_time, &tm1);
			time2string(sta->last_time,&tm2);

			printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
					sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
					(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
					convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
					(char *)P(tm1),(char *)P(tm2), id_index, par);

			free(tm1);
			free(tm2);

			id_index++;

			sta = sta->psta;

		}
		k++;
		if(k >= all_ap_num) break;

	}

exter_ap_end:

	if(al_sta_num > 0) {
		if(in_ap_num > 0 || ex_ap_num > 0)
			printf(",\n");

		printf("{\"name\":\"Unknown\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":%s}",
			id_index, "false");

		id_unknown = id_index;
		id_index++;

		draw_alone_sta_list(sta_list);
	}

	printf("]}\n");

	if(ap_list) free(ap_list);
	if(sta_list) free(sta_list);

	ap_list = NULL;
	sta_list = NULL;
	return 0;
}

char *time2string_mod(time_t time1, char *buf)
{
    struct tm tm1;
    if(time1 <= 0)
        return NULL;
    localtime_r(&time1, &tm1 );
    sprintf( buf, "%04d-%02d-%02d %02d:%02d:%02d",tm1.tm_year+1900, tm1.tm_mon+1, tm1.tm_mday,tm1.tm_hour, tm1.tm_min,tm1.tm_sec);
    return buf;
}


int serialize_wireless_tree_channel(char *ap_list, char *sta_list, struct w_node **array_2g, struct w_node **array_5g, int ap_num, int sta_num)
{
	int i,j,k,ch;
	struct w_node *ap, *sta, *tmp, *cur;

	in_ap_num	= 0;
	ex_ap_num	= 0;
	in_sta_num	= 0;
	ex_sta_num	= 0;
	al_sta_num	= 0;

	empty_2g = 0;
	empty_5g = 0;

	for(i=0; i<ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));

		if(ap->ipv4[0] != '\0')
			in_ap_num++;
		else
			ex_ap_num++;


		ch=convert_ap_channel(ap->channel);
		ap->channel=ch;
		ap->lastap=NULL;
		ap->sta_num=0;

		if(ap->freq_band == 2){			
			assert(ch>0 && ch<=CHANNEL_MAX_2G);
			empty_2g = 1;
			if(!array_2g[ch-1]){
				array_2g[ch-1]=ap;
			}
			else{
				cur=array_2g[ch-1];
				while(cur->lastap)	cur=cur->lastap;
				cur->lastap=ap;
			}
		}
		else{
			for( k = 0; k < CHANNEL_5G_NUM; k++){
				if(ap->channel == channel_5g[k]){
					empty_5g = 1;
					if(!array_5g[k])	array_5g[k]=ap;
					else{
						cur=array_5g[k];
						while(cur->lastap)	cur=cur->lastap;
						cur->lastap =ap;
					}					
				}
			}
		}

		for(j=0; j<sta_num; j++) {
			sta = (struct w_node *)(sta_list + sizeof(int) + j*sizeof(struct w_node));
			if(sta->freq_band == ap->freq_band && memcmp(ap->mac, sta->bssid, 6) == 0) {
				sta->psta=NULL;
				ap->sta_num++;
				sta->pap = ap;

				if(ap->ipv4[0] != '\0')
					in_sta_num++;
				else
					ex_sta_num++;

				if(ap->psta == NULL)
					ap->psta = sta;
				else {
					tmp = ap->psta;
					while(tmp->psta) {
						tmp = tmp->psta;
					}
					if(!tmp->psta)
						tmp->psta = sta;
				}
			}
		}
	}
	al_sta_num = all_sta_num - in_sta_num - ex_sta_num;
	return 0;
}

int wips_get_wireless_list_channel(void)
{
	int i,ap_parent,sta_parent;
	char *ap_list, *sta_list;
	struct w_node *ap, *sta;
	char tm1[64];
	char tm2[64];
    memset(tm1,0,64);    
    memset(tm2,0,64);
    struct w_node* ch[CHANNEL_MAX_2G];
    memset(ch,0,sizeof(struct w_node *)*CHANNEL_MAX_2G);

	struct w_node* ch1[CHANNEL_5G_NUM];
	memset(ch1,0,sizeof(struct w_node *)*CHANNEL_5G_NUM);


	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);


	sta_list = get_wips_data("stalist");
	if(sta_list == NULL) {
		free(ap_list);
		return 0;
	}

	all_sta_num =  *((int *)(sta_list));
	all_sta_num = all_sta_num/sizeof(struct w_node);

	serialize_wireless_tree_channel(ap_list, sta_list, ch, ch1, all_ap_num, all_sta_num);

	printf("{\"data\":[");

	id_index=2;

	if(empty_2g){
		printf("{\"name\":\"2.4G\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":1, \"_parent\":0, \"_level\":1, \"_is_leaf\":false}");
	
  	  for(i=CHANNEL_MIN_2G; i<=CHANNEL_MAX_2G; i++) {		//1~14
			if(ch[i-1]){
				id_index++;
				printf(",\n{\"name\":\"Channel %d\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":1, \"_level\":2, \"_is_leaf\":false}",i,id_index);

				ap_parent=id_index;
		
    			ap=ch[i-1];
    			while(ap != NULL){
    				get_stats_ssid(ap);
					deal_ssid(stats_ssid);
    				time2string_mod(ap->up_time, tm1);
    				time2string_mod(ap->last_time, tm2);
    				id_index++;
    				printf(",\n{\"name\":\"%s-%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
    					"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
    						(char *)P(stats_ssid),ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
    						(char *)P(ap->ipv4), (char *)P(ap->vendor), i, convert_ap_mode(ap->g_rates, ap->n_rates),(char *)P(ap->sec_type),
    						ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2), id_index, ap_parent, ap->sta_num>0?"false":"true");

    				sta_parent = id_index;

    				sta = ap->psta;
    				while(ap->sta_num > 0 && sta != NULL) {
    					time2string_mod(sta->up_time, tm1);
    					time2string_mod(sta->last_time, tm2);
    					id_index++;
    					printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
    						"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
    							sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
    							(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
    							convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
    							(char *)P(tm1),(char *)P(tm2), id_index, sta_parent);

    					sta = sta->psta;
    				}
    				ap=ap->lastap;
    			}
			}
   		 }
	}

	if(empty_5g){
		if(empty_2g) printf(",\n");
		printf("{\"name\":\"5G\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":2, \"_parent\":0, \"_level\":1, \"_is_leaf\":false}");

		for(i=0;i<CHANNEL_5G_NUM;i++){
			if(ch1[i]){
				id_index++;
				printf(",\n{\"name\":\"Channel %d\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":false}",channel_5g[i],id_index);

				ap_parent = id_index;
				ap=ch1[i];
				while(ap!=NULL){
					get_stats_ssid(ap);
					deal_ssid(stats_ssid);
    				time2string_mod(ap->up_time, tm1);
    				time2string_mod(ap->last_time, tm2);
    				id_index++;
					printf(",\n{\"name\":\"%s-%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
    					"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
    						(char *)P(stats_ssid),ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
    						(char *)P(ap->ipv4), (char *)P(ap->vendor), channel_5g[i], convert_ap_mode(ap->g_rates, ap->n_rates),(char *)P(ap->sec_type),
    						ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2), id_index, ap_parent, ap->sta_num>0?"false":"true");
				
					sta_parent = id_index;

    				sta = ap->psta;
    				while(ap->sta_num > 0 && sta != NULL) {
    					time2string_mod(sta->up_time, tm1);
    					time2string_mod(sta->last_time, tm2);
    					id_index++;
    					printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
    						"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
    							sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
    							(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
    							convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
    							(char *)P(tm1),(char *)P(tm2), id_index, sta_parent);

    					sta = sta->psta;
    				}
    				ap=ap->lastap;
				}
			}
		}
	}

	printf("]}\n");
	if(ap_list) free(ap_list);
	if(sta_list) free(sta_list);
	ap_list = NULL;
	sta_list = NULL;
	return 0;
}

int wips_get_wireless_list_channel_old(void)
{
	int i,j,ap_parent,sta_parent;
	char *ap_list, *sta_list;
	struct w_node *ap, *sta;
	char *tm1, *tm2;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);


	sta_list = get_wips_data("stalist");
	if(sta_list == NULL) {
		free(ap_list);
		return 0;
	}

	all_sta_num =  *((int *)(sta_list));
	all_sta_num = all_sta_num/sizeof(struct w_node);

	serialize_wireless_tree(ap_list, sta_list, all_ap_num, all_sta_num);

	printf("{\"data\":[");

   	id_index = CHANNEL_MAX_2G + 1;
    for(i=CHANNEL_MIN_2G; i<=CHANNEL_MAX_2G; i++) {

		ap_parent = i;
		if(i == CHANNEL_MIN_2G) {
			printf("{\"name\":\"Channel %d\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":0, \"_level\":1, \"_is_leaf\":false}",i,i);
		}
		else
			printf(",\n{\"name\":\"Channel %d\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":0, \"_level\":1, \"_is_leaf\":false}",i,i);

    	for(j=0; j<all_ap_num; j++) {

    		ap = (struct w_node *)(ap_list + sizeof(int) + j*sizeof(struct w_node));
    		if(convert_ap_channel(ap->channel) != i) {
                continue;
    		}

    		get_stats_ssid(ap);
		deal_ssid((char *)&stats_ssid[0]);
    		time2string(ap->up_time, &tm1);
    		time2string(ap->last_time,&tm2);

    		printf(",\n{\"name\":\"%s-%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
    			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
    				(char *)P(stats_ssid),ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
    				(char *)P(ap->ipv4), (char *)P(ap->vendor), convert_ap_channel(ap->channel),
    				convert_ap_mode(ap->g_rates, ap->n_rates),(char *)P(ap->sec_type),
    				ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2),
    				id_index, ap_parent, ap->sta_num>0?"false":"true");

    		sta_parent = id_index;
    		id_index++;

    		free(tm1);
    		free(tm2);

    		ap->id = id_index;
    		id_unknown = 0;

    		sta = ap->psta;

    		while(ap->sta_num && sta != NULL) {

    			time2string(sta->up_time, &tm1);
    			time2string(sta->last_time,&tm2);

    			printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
    				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
    					sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
    					(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
    					convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
    					(char *)P(tm1),(char *)P(tm2), id_index, sta_parent);

    			free(tm1);
    			free(tm2);

    			id_index++;

    			sta = sta->psta;

    		}


    	}
    }

	printf("]}\n");

	if(ap_list) free(ap_list);
	if(sta_list) free(sta_list);

	ap_list = NULL;
	sta_list = NULL;
	return 0;
}

int is_empty_mac(__u8 *mac)
{
    if(mac[0] == 0 && mac[1] == 0 && mac[2] == 0
        && mac[3] == 0 && mac[4] == 0 && mac[5] == 0)
        return 0;

    return 1;
}

int set_empty_mac(__u8 *mac)
{
    mac[0] = 0;
    mac[1] = 0;
    mac[2] = 0;
    mac[3] = 0;
    mac[4] = 0;
    mac[5] = 0;

    return 0;
}





int wips_get_wireless_list_ssid_old(void)
{
	char tmp1[64];
	char tmp2[64];
    memset(tmp1,0,64);    
    memset(tmp2,0,64);
	char *node_list;
	struct w_node *cur,*tmp_cur,*tmp_cur1;
	struct w_node *inter_list=NULL,*exter_list=NULL,*cur_inter=NULL,*cur_exter=NULL,*unknown_list=NULL,*cur_unknown=NULL;
	int node_num,first=0,in_node_num=0,ex_node_num=0,un_node_num=0;
	char pre_ssid[256];

	node_list = get_wips_data("TREE_GET_ALL_ESSID");
	if(node_list == NULL) {
		return 0;
	}

	node_num = *(int *)node_list;
	node_num = node_num/sizeof(struct w_node);

	if(node_num<1)	return 0;           //at least one w_node

	int i=0,j=0,k=0,l=0,head_inter=0,head_exter=0,head_unknown=0,is_in=0,add_step=0;
	//cur =(struct w_node *)(node_list+sizeof(int));

	while(i<node_num)
	{
		j=i+1;
		cur=(struct w_node *)(node_list+sizeof(int)+i*sizeof(struct w_node));
		tmp_cur=cur;
		is_in=0;	//default is external
		k=0;
		//get_stats_ssid(cur);
		//memcpy(pre_ssid,stats_ssid,256);
		if(cur->ipv4[0]!='\0')	is_in=1;	//current node determine these group's type
		/*
		while(j<node_num){
			tmp_cur++;			
			get_stats_ssid(tmp_cur);
			if(stats_ssid[0] == '\0'){		//hiding ssid
				if(tmp_cur->ipv4[0]!='\0')	is_in=1;
				j++;
				continue;
			}
			if(strcmp(pre_ssid,stats_ssid))	break;	//not the same group,then break
			if(tmp_cur->ipv4[0]!='\0')	is_in=1;		
			j++;	//not break,then plus one	
		}*/
		while(j<node_num){
			tmp_cur++;
			if(tmp_cur->node_type&1)		break;
			if(tmp_cur->ipv4[0]!='\0' && !memcmp((void *)(tmp_cur->bssid),(void *)(cur->mac),sizeof(char)*6)){
				is_in=1;
			}
			j++;
		}
		add_step=j-i;	//almost (j-i) nodes belong to one group,they are internal/external and unknown
		tmp_cur=cur;
		if(is_in){		//internal or unknown
			while(k<add_step){
				tmp_cur=cur+k;
				if(!head_inter){		//first time to add to internal list
					if(tmp_cur->node_type&1){	//ap
						head_inter=1;
						inter_list=tmp_cur;
						cur_inter=tmp_cur;
						in_node_num++;
					}
					else{	//unvalid sta,add to unknown list
						if(!head_unknown){		//fisrt time to add to unknown list
							head_unknown=1;
							unknown_list=tmp_cur;
							cur_unknown=tmp_cur;
						}
						else{					//not the first time to add to unknown list
							cur_unknown->psta=tmp_cur;
							cur_unknown=tmp_cur;
						}
						un_node_num++;
					}
				}
				else{              //not the first time to add to internal list
					if(tmp_cur->node_type&1){     //add ap to internal list directly
						cur_inter->psta=tmp_cur;
						cur_inter=tmp_cur;
						in_node_num++;
					}
					else{		//sta must be analysed
						tmp_cur1=cur;
						l=0;
						while(l<add_step){
							tmp_cur1=cur+l;
							if(tmp_cur1->node_type&1){   //find parent
								if(!memcmp((void *)(tmp_cur1->mac),(void *)(tmp_cur->bssid),sizeof(char)*6)){
									cur_inter->psta=tmp_cur;
									cur_inter=tmp_cur;
									in_node_num++;
									break;
								}
							}
							l++;
						}
						if(l==add_step){    //can not find parent,the loney sta have to add to unknown list
							if(!head_unknown){		//fisrt time to add to unknown list
								head_unknown=1;
								unknown_list=tmp_cur;
								cur_unknown=tmp_cur;
							}
							else{					//not the first time to add to unknown list
								cur_unknown->psta=tmp_cur;
								cur_unknown=tmp_cur;
							}
							un_node_num++;
						}
					}
				}
				k++;
			}	
		}
		else{		//external or unknown
			while(k<add_step){
				tmp_cur=cur+k;
				if(!head_exter){		//first time to add to external list
					if(tmp_cur->node_type&1){	//ap
						head_exter=1;
						exter_list=tmp_cur;
						cur_exter=tmp_cur;
						ex_node_num++;
					}
					else{	//unvalid sta,add to unknown list
						if(!head_unknown){		//fisrt time to add to unknown list
							head_unknown=1;
							unknown_list=tmp_cur;
							cur_unknown=tmp_cur;
						}
						else{					//not the first time to add to unknown list
							cur_unknown->psta=tmp_cur;
							cur_unknown=tmp_cur;
						}
						un_node_num++;
					}
				}
				else{              //not the first time to add to external list
					if(tmp_cur->node_type&1){     //add ap to external list directly
						cur_exter->psta=tmp_cur;
						cur_exter=tmp_cur;
						ex_node_num++;
					}
					else{		//sta must be analysed
						tmp_cur1=cur;
						l=0;
						while(l<add_step){
							tmp_cur1=cur+l;
							if(tmp_cur1->node_type&1){   //find parent
								if(!memcmp((void *)(tmp_cur1->mac),(void *)(tmp_cur->bssid),sizeof(char)*6)){
									cur_exter->psta=tmp_cur;
									cur_exter=tmp_cur;
									ex_node_num++;
									break;
								}
							}
							l++;
						}
						if(l==add_step){    //can not find parent,the loney sta have to add to unknown list
							if(!head_unknown){		//fisrt time to add to unknown list
								head_unknown=1;
								unknown_list=tmp_cur;
								cur_unknown=tmp_cur;
							}
							else{					//not the first time to add to unknown list
								cur_unknown->psta=tmp_cur;
								cur_unknown=tmp_cur;
							}
							un_node_num++;
						}
					}
				}
				k++;
			}
		}
		i=i+add_step;
	}
	if(cur_exter)	cur_exter->psta=NULL;
	if(cur_inter)	cur_inter->psta=NULL;
	if(cur_unknown)	cur_unknown->psta=NULL;
	cur_exter=exter_list;
	cur_inter=inter_list;
	cur_unknown=unknown_list;

	id_index = 4;    //'1' is internal root,'2' is external root,'3' is unknown root,so begin with '4'	
	int ap_parent=0,sta_parent=0;
	printf("{\"data\":[");
	if(in_node_num>0){
		assert(inter_list);
		while(cur_inter!=NULL){             //internal node
			get_stats_ssid(cur_inter);
			if(stats_ssid[0] == '\0') {
				if(first==0){
					sprintf(stats_ssid,"HidingSSID");
				}
				else{
					memcpy(stats_ssid, pre_ssid,256);	
				}
			}
			deal_ssid(stats_ssid);

			if(cur_inter->node_type&1){           //ap

				if(first==0){                     //data head
					//parent = 1;
					first++;
					printf("{\"name\":\"Internal\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
					"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":1, \"_parent\":0, \"_level\":1, \"_is_leaf\":false},\n");

					printf("{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
					"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":1, \"_level\":2, \"_is_leaf\":false}",
					stats_ssid, id_index);	
					memcpy(pre_ssid,stats_ssid,256);
					ap_parent=id_index;
				}
				else{
					if(strcmp(pre_ssid,stats_ssid)){          //ssid group head
						id_index++;
						printf(",\n{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
						"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":1, \"_level\":2, \"_is_leaf\":false}",
						stats_ssid, id_index);
						strcpy(pre_ssid,stats_ssid);
						ap_parent=id_index;
					}
				}


					id_index++;                               //ap's data
					time2string_mod(cur_inter->up_time,tmp1);
					time2string_mod(cur_inter->last_time,tmp2);
					printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
		    			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
		    				cur_inter->mac[0],cur_inter->mac[1],cur_inter->mac[2],cur_inter->mac[3],cur_inter->mac[4],cur_inter->mac[5],
		    				(char *)P(cur_inter->ipv4), (char *)P(cur_inter->vendor), convert_ap_channel(cur_inter->channel),
		    				convert_ap_mode(cur_inter->g_rates, cur_inter->n_rates),(char *)P(cur_inter->sec_type),
		    				cur_inter->signal, cur_inter->noise, (char *)P(tmp1), (char *)P(tmp2),
		    				id_index, ap_parent, (!cur_inter->psta)||((cur_inter->psta->node_type)&1)?"true":"false");

					sta_parent=id_index;
			}
			else{                               //sta
				id_index++;
				time2string_mod(cur_inter->up_time,tmp1);
				time2string_mod(cur_inter->last_time,tmp2);
				printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
	    				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
						cur_inter->mac[0],cur_inter->mac[1],cur_inter->mac[2],cur_inter->mac[3],cur_inter->mac[4],cur_inter->mac[5],
						(char *)P(cur_inter->ipv4), (char *)P(cur_inter->vendor), convert_ap_channel(cur_inter->channel),
						convert_sta_rate(cur_inter->rates), "", cur_inter->signal, cur_inter->noise,
						(char *)P(tmp1),(char *)P(tmp2), id_index, sta_parent);
			}
			cur_inter=cur_inter->psta;
		}
	}

	if(ex_node_num>0){             //external node
		assert(exter_list);
		first=0;
		while(cur_exter!=NULL){
			get_stats_ssid(cur_exter);
			if(stats_ssid[0] == '\0'){
				if(first==0){
					sprintf(stats_ssid,"HidingSSID");
				}
				else	{
					memcpy(stats_ssid, pre_ssid,256);	
				}
			}
			deal_ssid(stats_ssid);
			if(cur_exter->node_type&1){           //ap
				if(first==0){                     //data head
					first++;
					if(in_node_num>0){
						printf(",\n");
						id_index++;
					}

					printf("{\"name\":\"External\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
					"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":2, \"_parent\":0, \"_level\":1, \"_is_leaf\":false},\n");

					printf("{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
					"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":false}",
					stats_ssid, id_index);	
					memcpy(pre_ssid,stats_ssid,256);
					ap_parent=id_index;
				}
				else{
					if(strcmp(pre_ssid,stats_ssid)){          //ssid group head
						id_index++;
						printf(",\n{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
						"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":false}",
						stats_ssid, id_index);
						strcpy(pre_ssid,stats_ssid);
						ap_parent=id_index;
					}
				}

				id_index++;
					time2string_mod(cur_exter->up_time,tmp1);
					time2string_mod(cur_exter->last_time,tmp2);
					printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
		    			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
		    				cur_exter->mac[0],cur_exter->mac[1],cur_exter->mac[2],cur_exter->mac[3],cur_exter->mac[4],cur_exter->mac[5],
		    				(char *)P(cur_exter->ipv4), (char *)P(cur_exter->vendor), convert_ap_channel(cur_exter->channel),
		    				convert_ap_mode(cur_exter->g_rates, cur_exter->n_rates),(char *)P(cur_exter->sec_type),
		    				cur_exter->signal, cur_exter->noise, (char *)P(tmp1), (char *)P(tmp2),
		    				id_index, ap_parent, (!cur_exter->psta)||((cur_exter->psta->node_type)&1)?"true":"false");

					sta_parent=id_index;

			}
			else{                               //sta
				id_index++;
				time2string_mod(cur_exter->up_time,tmp1);
				time2string_mod(cur_exter->last_time,tmp2);
				printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
	    				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
						cur_exter->mac[0],cur_exter->mac[1],cur_exter->mac[2],cur_exter->mac[3],cur_exter->mac[4],cur_exter->mac[5],
						(char *)P(cur_exter->ipv4), (char *)P(cur_exter->vendor), convert_ap_channel(cur_exter->channel),
						convert_sta_rate(cur_exter->rates), "", cur_exter->signal, cur_exter->noise,
						(char *)P(tmp1),(char *)P(tmp2), id_index, sta_parent);
			}

			cur_exter=cur_exter->psta;
		}		
	}

	if(un_node_num>0){
		assert(unknown_list);
		if(in_node_num>0||ex_node_num>0){
			printf(",\n");
		}

		printf("{\"name\":\"Unknown\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":3, \"_parent\":0, \"_level\":1, \"_is_leaf\":false}");

		while(cur_unknown!=NULL){
			id_index++;
			time2string_mod(cur_unknown->up_time,tmp1);
			time2string_mod(cur_unknown->last_time,tmp2);
			printf(",\n{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
    				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":3, \"_level\":2, \"_is_leaf\":true}",
					cur_unknown->mac[0],cur_unknown->mac[1],cur_unknown->mac[2],cur_unknown->mac[3],cur_unknown->mac[4],cur_unknown->mac[5],
					(char *)P(cur_unknown->ipv4), (char *)P(cur_unknown->vendor), convert_ap_channel(cur_unknown->channel),
					convert_sta_rate(cur_unknown->rates), "", cur_unknown->signal, cur_unknown->noise,
					(char *)P(tmp1),(char *)P(tmp2), id_index);
			cur_unknown=cur_unknown->psta;
		}
	}
	printf("]}\n");
	if(node_list) free(node_list);
	node_list = NULL;
	return 0;
}


int wips_get_wireless_list_ssid(void)
{
	int i,k,par,first = 0;
	int ap_parent, sta_parent;
	char *ap_list, *sta_list;
	struct w_node *ap, *sta;
	char *tm1, *tm2;

	struct w_ssid inter_ssid_list[SSID_MAX_NUM];
	struct w_ssid exter_ssid_list[SSID_MAX_NUM];

	memset(&inter_ssid_list, 0, sizeof(struct w_ssid)*SSID_MAX_NUM);
	memset(&exter_ssid_list, 0, sizeof(struct w_ssid)*SSID_MAX_NUM);

	ap_list = get_wips_data("aplist");

	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);


	sta_list = get_wips_data("stalist");
	if(sta_list == NULL) {
		free(ap_list);
		return 0;
	}

	all_sta_num =  *((int *)(sta_list));
	all_sta_num = all_sta_num/sizeof(struct w_node);

	serialize_wireless_ssid(inter_ssid_list, exter_ssid_list, ap_list, sta_list, all_ap_num, all_sta_num);

/*    for(i=0; i<SSID_MAX_NUM; i++) {
        if(ssid_list[i].ssid[0] == '\0')
            continue;
        printf("\nssid_list %d:%d %d %s", i, ssid_list[i].type, ssid_list[i].pap,ssid_list[i].ssid);
    }*/

	printf("{\"data\":[");

	id_index = 3;
	k = 0;
	if(in_ssid_num>0){
		for(i=0; i<SSID_MAX_NUM; i++) {

			if(inter_ssid_list[i].ssid[0] == '\0')
				break;
			if(inter_ssid_list[i].type != 1 || inter_ssid_list[i].pap == NULL)
				continue;

			deal_ssid((char *)&inter_ssid_list[i].ssid[0]);

			if(first == 0) {
				parent = 1;
				first++;
				printf("{\"name\":\"Internal\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":1, \"_parent\":0, \"_level\":1, \"_is_leaf\":false},\n");

				printf("{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":1, \"_level\":2, \"_is_leaf\":false},\n",
				inter_ssid_list[i].ssid, id_index);
			}
			else
				printf(",\n{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":1, \"_level\":2, \"_is_leaf\":false},\n",
				inter_ssid_list[i].ssid, id_index);

			ap_parent = id_index;
			id_index++;

			ap = inter_ssid_list[i].pap;
			while(ap != NULL) {

	    		time2string(ap->up_time, &tm1);
	    		time2string(ap->last_time,&tm2);

	    		printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":%d,\"mode\":\"%s\",\"sec\":\"%s\","
	    			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
	    				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
	    				(char *)P(ap->ipv4), (char *)P(ap->vendor), convert_ap_channel(ap->channel),
	    				convert_ap_mode(ap->g_rates, ap->n_rates),(char *)P(ap->sec_type),
	    				ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2),
	    				id_index, ap_parent, ap->sta_num>0?"false":"true");

	    		free(tm1);
	    		free(tm2);

	    		ap->id = id_index;
	    		sta_parent = id_index;
	    		id_index++;
	    		id_unknown = 0;

	    		sta = ap->psta;

	    		while(ap->sta_num && sta != NULL) {

	    			par = id_unknown;
	    			if(par <= 0)
	    				par = parent;

	    			printf(",\n");

	    			time2string(sta->up_time, &tm1);
	    			time2string(sta->last_time,&tm2);

	    			printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
	    				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
	    					sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
	    					(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
	    					convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
	    					(char *)P(tm1),(char *)P(tm2), id_index, sta_parent);

	    			free(tm1);
	    			free(tm2);

	    			id_index++;

	    			sta = sta->psta;

	    		}

			if(ap->pap != NULL)
				printf(",\n");
	    		ap = ap->pap;
				
			}
		}
	}


	k = 0;
	first = 0;
	if(ex_ssid_num>0){
		for(i=0; i<SSID_MAX_NUM; i++) {

			if(exter_ssid_list[i].ssid[0] == '\0')
				break;

			if(exter_ssid_list[i].type != 2 || exter_ssid_list[i].pap == NULL)
				continue;

			deal_ssid((char *)&exter_ssid_list[i].ssid[0]);

			if(first == 0) {
				parent = 1;
				first++;
				if(in_ssid_num > 0)
					printf(",\n");
			
				id_index++;
				printf("{\"name\":\"External\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":2, \"_parent\":0, \"_level\":1, \"_is_leaf\":false},\n");

				printf("{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
    				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":false},\n",
    				exter_ssid_list[i].ssid, id_index);
			}
			else
				printf(",\n{\"name\":\"%s\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
    				"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":false},\n",
    				exter_ssid_list[i].ssid, id_index);

			ap_parent = id_index;
			id_index++;

			ap = exter_ssid_list[i].pap;
			while(ap != NULL) {

	    		time2string(ap->up_time, &tm1);
	    		time2string(ap->last_time,&tm2);

	    		printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
	    			"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":3, \"_is_leaf\":%s}",
	    				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5],
	    				(char *)P(ap->ipv4), (char *)P(ap->vendor), convert_ap_channel(ap->channel),
	    				convert_ap_mode(ap->g_rates, ap->n_rates), (char *)P(ap->sec_type),
	    				ap->signal, ap->noise, (char *)P(tm1), (char *)P(tm2),
	    				id_index, ap_parent, ap->sta_num>0?"false":"true");

	    		free(tm1);
	    		free(tm2);

	    		ap->id = id_index;
	    		sta_parent = id_index;
	    		id_index++;
	    		id_unknown = 0;

	    		sta = ap->psta;

	    		while(ap->sta_num && sta != NULL) {

	    			par = id_unknown;
	    			if(par <= 0)
	    				par = parent;

	    			printf(",\n");

	    			time2string(sta->up_time, &tm1);
	    			time2string(sta->last_time,&tm2);

	    			printf("{\"name\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ip\":\"%s\", \"vendor\":\"%s\",\"ch\":\"%d\",\"mode\":\"%s\",\"sec\":\"%s\","
	    				"\"rssi\":%d,\"noise\":%d,\"t1\":\"%s\",\"t2\":\"%s\", \"_id\":%d, \"_parent\":%d, \"_level\":4, \"_is_leaf\":true}",
	    					sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5],
	    					(char *)P(sta->ipv4), (char *)P(sta->vendor), convert_ap_channel(sta->channel),
	    					convert_sta_rate(sta->rates), "", sta->signal, sta->noise,
	    					(char *)P(tm1),(char *)P(tm2), id_index, sta_parent);

	    			free(tm1);
	    			free(tm2);

	    			id_index++;

	    			sta = sta->psta;

	    		}

				if(ap->pap != NULL)
					printf(",\n");
				ap = ap->pap;
				
			}
		}
	}


	if(al_sta_num > 0) {
		if(in_ssid_num > 0 || ex_ssid_num > 0)
			printf(",\n");

		printf("{\"name\":\"Unknown\", \"ip\":\"\", \"vendor\":\"\",\"ch\":\"\",\"mode\":\"\",\"sec\":\"\","
			"\"rssi\":\"\",\"noise\":\"\",\"t1\":\"\",\"t2\":\"\",\"_id\":%d, \"_parent\":2, \"_level\":2, \"_is_leaf\":%s}",
			id_index, "false");

		id_unknown = id_index;
		id_index++;

		draw_alone_sta_list(sta_list);
	}

	printf("]}\n");

	if(ap_list) free(ap_list);
	if(sta_list) free(sta_list);

	ap_list = NULL;
	sta_list = NULL;
	return 0;
}



int wips_get_topology_total(void)
{
	int inter_area=50;
	int inter_volume_x,inter_volume_y,exter_volume_x,exter_volume_y;
	int inter_ap_row, inter_ap_column, inter_sta_row, inter_sta_column;
	int exter_ap_row, exter_ap_column, exter_sta_row, exter_sta_column;
	int inter_ap_step_x,inter_ap_step_y,exter_ap_step_x,exter_ap_step_y;

	int px,py;

	int i,j,k;
	char *ap_list, *sta_list;
	char  mac[24];
	struct w_node *ap;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);


	sta_list = get_wips_data("stalist");
	if(sta_list == NULL) {
		free(ap_list);
		return 0;
	}

	all_sta_num =  *((int *)(sta_list));
	all_sta_num = all_sta_num/sizeof(struct w_node);

	serialize_wireless_tree(ap_list, sta_list, all_ap_num, all_sta_num);

	/*--------------------------------------------------------------------------*/

	if((in_ap_num + in_sta_num + ex_ap_num + ex_sta_num) != 0)
		inter_area = (in_ap_num*2 + in_sta_num/2 + 5)*100/(in_ap_num*2 + in_sta_num + ex_ap_num + ex_sta_num/2 + 5);

//fprintf(msg, " inter_area=%d\r\n gnInterApNum=%d  gnExterApNum=%d\r\n gnInterStaNum=%d  gnExterStaNum=%d\r\n",inter_area,gnInterApNum,gnExterApNum,gnInterStaNum,gnExterStaNum);

	if(pgWidth == 0) pgWidth = 1024;
	if(pgHeight == 0) pgHeight = 768;

	if(inter_area != 0) {
		inter_volume_x = pgWidth*100/inter_area/(AP_PIX_X*2);
		inter_volume_y = pgHeight/(AP_PIX_Y*2) ;
		if(inter_volume_y > 1) inter_volume_y--;
	}
	else {
		inter_volume_x = 0;
		inter_volume_y = 0;
	}

	if(inter_area == 100) {
		exter_volume_x = 0;
		exter_volume_y = 0;
	}
	else {
		exter_volume_x = pgWidth*100/(100-inter_area)/(AP_PIX_X*2);
		exter_volume_y = pgHeight/(AP_PIX_Y*2) ;
	}
//fprintf(msg, " pgWidth=%d pgHeight=%d\r\n",pgWidth,pgHeight);
//fprintf(msg, " inter_volume_x=%d  inter_volume_y=%d\r\n exter_volume_x=%d  exter_volume_y=%d\r\n",inter_volume_x,inter_volume_y,exter_volume_x,exter_volume_y);
//fprintf(msg, " gnInterApNum=%d  gnExterApNum=%d\r\n gnInterStaNum=%d  gnExterStaNum=%d\r\n",gnInterApNum,gnExterApNum,gnInterStaNum,gnExterStaNum);

	/*when too more AP, drop External AP*/
/*	if((inter_volume_x * inter_volume_y)	< (gnInterApNum + gnInterStaNum) ||
		(exter_volume_x * exter_volume_y)	< (gnExterApNum + gnExterStaNum)) {
		gnExterApNum = 0;
		inter_area = 100;
	}*/

	if(inter_volume_y != 0)
		inter_ap_row = in_ap_num/inter_volume_y;
	else
		inter_ap_row = 2;

	if(inter_ap_row == 0)
		inter_ap_row = 2;

	if((inter_ap_row % 2)!=0 || !inter_ap_row)
		inter_ap_row++;

	inter_ap_column = in_ap_num/inter_ap_row;

	if(((in_ap_num + in_sta_num) && !inter_ap_column) || (in_ap_num % inter_ap_row))
		inter_ap_column++;

	inter_sta_row = inter_ap_row*2;
	inter_sta_column = inter_ap_column;

	inter_ap_step_x = 	inter_area/(inter_ap_column+1);
	inter_ap_step_y = 50/(inter_ap_row/2+1);
	if(inter_ap_step_y > 25) inter_ap_step_y = 25;

	if(exter_volume_y  != 0)
		exter_ap_row = (ex_ap_num /*+ gnAloneStaNum*/)/exter_volume_y;
	else
		exter_ap_row = 0;

	if((ex_ap_num /*+ gnAloneStaNum*/) && !exter_ap_row)
		exter_ap_row++;

	if(exter_ap_row != 0)
		exter_ap_column = (ex_ap_num/* + gnAloneStaNum*/)/exter_ap_row;
	else
		exter_ap_column = 0;

	if((ex_ap_num /*+ gnAloneStaNum*/) && !exter_ap_column)
		exter_ap_column++;

	exter_sta_row = exter_ap_row*2;
	exter_sta_column = exter_ap_column;

	exter_ap_step_x = (100 - inter_area)/(exter_ap_column+1);
	exter_ap_step_y = 100/(exter_ap_row+1);

//fprintf(msg, "inter_ap_row=%d  inter_ap_column=%d\r\n",inter_ap_row,inter_ap_column);
//fprintf(msg, "exter_ap_row=%d  exter_ap_column=%d\r\n",exter_ap_row,exter_ap_column);

//fprintf(msg, "inter_ap_step_x=%d  inter_ap_step_y=%d\r\n",inter_ap_step_x,inter_ap_step_y);
//fprintf(msg, "exter_ap_step_x=%d  exter_ap_step_y=%d\r\n",exter_ap_step_x,exter_ap_step_y);


	printf("<chart palette='2' bgColor='ffffff' showBorder='0' xAxisMinValue='0' xAxisMaxValue='100' yAxisMinValue='0' "
		"yAxisMaxValue='100' is3D='1' showFormBtn='1' viewMode='0' enableLink='1' unescapeLinks='0' "/*enableDrag='1' "*/
		"showFormBtn='1' formBtnTitle='清空图表' formAction=''>\n");
	printf("<dataset plotBorderAlpha='0'>\n");

//	printf("<set x='%d' y='50' radius='20' width='64' height='40' shape='circle' name='Internet' color='33C1FE' id='internet' /> \n",inter_area/4);
	printf("<set x='%d' y='50' width='32' height='37' name='wips' color='33C1FE' id='wips' imageNode='1' "
		"imageURL='images/wips.png' labelAlign='MIDDLE' alpha='0'  /> \n",inter_area/2);

	/* draw internal ap & sta */
	k = 0;
	for(i=1; i<=inter_ap_row; i++) {
		for(j=1; j<=inter_ap_column; j++) {

			/* get internal ap*/
			ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
			while(ap->ipv4[0] == '\0') {
				k++;
				if(k >= all_ap_num)
					goto inter_ap_end;
				ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
			}

			px = inter_ap_step_x * j;

			if(i > (inter_ap_row/2) && (inter_ap_row !=1))
				py = inter_ap_step_y * (i+1);
			else
				py = inter_ap_step_y * i;

			sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);

			get_stats_ssid(ap);
			deal_ssid((char *)&stats_ssid[0]);

			if(ap->channel > 2000)
				printf("<set x='%d' y='%d' width='%d' height='%d' name='%s' color='33C1FE' id='%s' "
					"imageNode='1' imageURL='images/ap.png' alpha='0' imageAlign='MIDDLE' toolText='%s\n%s\n%s\n%d MHz' "
					"link=\"JavaScript:viewAP('%s');\" /> \n" , px,py, AP_PIX_X,AP_PIX_Y,
					(char *)P(stats_ssid),
					mac,
					(char *)P(stats_ssid),
					ap->ipv4,
					mac,
					ap->channel,
					mac);
			else
				printf("<set x='%d' y='%d' width='%d' height='%d' name='%s' color='33C1FE' id='%s' "
					"imageNode='1' imageURL='images/ap.png' alpha='0' imageAlign='MIDDLE' toolText='%s\n%s\n%s\n%d' "
					"link=\"JavaScript:viewAP('%s');\" /> \n" , px,py, AP_PIX_X,AP_PIX_Y,
					(char *)P(stats_ssid),
					mac,
					(char *)P(stats_ssid),
					ap->ipv4,
					mac,
					ap->channel,
					mac);

			if(ap->sta_num > 0) {

//				if(ap->sta_num > 16)
//					ap->sta_num = 16;		//最多画16个STA
					
				if(ap->sta_num > 8) {
					/*sta_step_x = inter_ap_step_x*3/2/8;
					if(sta_step_x == 0)*/ sta_step_x = 1;
					sta_step_y = inter_ap_step_y/3;
					sta_row_num = 2;
					sta_px = px - 4*sta_step_x;
				}
				else {
					/*if(ap->sta_num != -1)
						sta_step_x = inter_ap_step_x*3/2/(ap->sta_num +1);
					if(sta_step_x == 0)*/ sta_step_x = 1;
					sta_step_y = inter_ap_step_y/2;
					sta_row_num = 1;
					sta_px = px - ap->sta_num*sta_step_x/2;
				}

				if(i > (inter_ap_row/2) && (inter_ap_row !=1))
					sta_step_y = 0 - sta_step_y;

				sta_py = py - sta_step_y;
				sta_column_num = 0;

				draw_association_sta(ap);
			}

			k++;
			if(k >= all_ap_num) break;

		}
		if(k >= all_ap_num) break;
	}

inter_ap_end:

	/* draw external ap & sta */
	k = 0;
	for(i=exter_ap_row; i>0; i--) {
//fprintf(msg, "\r\n");

		for(j=1; j<=exter_ap_column; j++) {

			/* get external ap*/
			ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
			while(ap->ipv4[0] != '\0') {
				k++;
				if(k >= all_ap_num)
					goto exter_ap_end;
				ap = (struct w_node *)(ap_list + sizeof(int) + k*sizeof(struct w_node));
			}

			px = inter_area + exter_ap_step_x * j;
			py = exter_ap_step_y * i;
//fprintf(msg, "px=%d  py=%d,  ",px,py);

			sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
				ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);

			get_stats_ssid(ap);
			deal_ssid((char *)&stats_ssid[0]);

			if(ap->channel > 2000)
				printf("<set x='%d' y='%d' width='%d' height='%d' name='%s' color='33C1FE' id='%s' "
					"imageNode='1' imageURL='images/ap.png' alpha='0' imageAlign='MIDDLE' toolText='%s\n%s\n%d MHz' "
					"link=\"JavaScript:viewAP('%s');\" /> \n" , px,py, AP_PIX_X,AP_PIX_Y,
					(char *)P(stats_ssid),
					mac,
					(char *)P(stats_ssid),
					mac,
					ap->channel,
					mac);
			else
				printf("<set x='%d' y='%d' width='%d' height='%d' name='%s' color='33C1FE' id='%s' "
					"imageNode='1' imageURL='images/ap.png' alpha='0' imageAlign='MIDDLE' toolText='%s\n%s\n%d' "
					"link=\"JavaScript:viewAP('%s');\" /> \n" , px,py, AP_PIX_X,AP_PIX_Y,
					(char *)P(stats_ssid),
					mac,
					(char *)P(stats_ssid),
					mac,
					ap->channel,
					mac);

			if(ap->sta_num > 0) {

//				if(ap->sta_num > 16)
//					ap->sta_num = 16;		//最多画16个STA
				
				if(ap->sta_num > 8) {
					/*sta_step_x = exter_ap_step_x*3/2/8;
					if(sta_step_x == 0)*/ sta_step_x = 1;
					sta_step_y = exter_ap_step_y/3;
					sta_row_num = 2;
					sta_px = px - 4*sta_step_x;
				} else {
					/*if(ap->sta_num != -1)
						sta_step_x = exter_ap_step_x*3/2/(ap->sta_num+1);
					if(sta_step_x == 0) */sta_step_x = 1;
					sta_step_y = exter_ap_step_y/2;
					sta_row_num = 1;
					sta_px = px - ap->sta_num*sta_step_x/2;
				}

				sta_py = py - sta_step_y;
				sta_column_num = 0;

				draw_association_sta(ap);
			}

			k++;
			if(k >= all_ap_num) {
				break;
			}

		}
		if(k >= all_ap_num) break;
	}

exter_ap_end:


	y_start = exter_ap_step_y*exter_ap_row;
	sta_px = 1;
	sta_py = 1;

	sta_step_x = exter_ap_step_x/2;
	sta_step_y = exter_ap_step_y/2;
	sta_row_num = 		exter_ap_row*2;
	sta_column_num =	exter_ap_column*2;
	x_start = inter_area;
	if(sta_step_x < 1) sta_step_x = 1;
	if(sta_step_y < 1) sta_step_y = 1;

	/* alone station should be draw here*/
	draw_alone_sta(sta_list);

	printf("</dataset>\n");
	printf("<connectors color='FF0000' stdThickness='5'>\n");

	draw_inter_ap_connector(ap_list);

	draw_sta_connector(sta_list);

	printf("</connectors>\n");
	printf("<vTrendlines>\n");
	printf("<line startValue='0' endValue='%d' color='00FF00' alpha='5' displayValue='Internal Network' isTrendZone='1' /> \n",inter_area);
	printf("<line startValue='%d' endValue='100' color='0000FF' alpha='5' displayValue='External Network' isTrendZone='1' /> \n",inter_area);
	printf("</vTrendlines>\n");
	printf("</chart>\n");

	if(ap_list) free(ap_list);
	if(sta_list) free(sta_list);

	ap_list = NULL;
	sta_list = NULL;

	return 0;
}


int wips_get_scatter_total(int mode)
{
	int i;
	char *ap_list;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);

/*	printf("<chart palette='1' caption='无线网络分布' subcaption='AP分布图' bgColor='ffffff' "
		"showBorder='0' yAxisName='Noise' xAxisName='Signal' showLegend='1' showNames='1' "
		"xAxisMaxValue='1.00' xAxisMinValue='0.01' >\n");*/
	if(mode == 2 ){
		printf("<chart palette='1' caption='无线网络分布' subcaption='AP分布图' bgColor='E7F0F9' "
			"showBorder='0' yAxisName='Channel' xAxisName='Signal' showLegend='1' showNames='1' "
			"xAxisMaxValue='100' xAxisMinValue='10' yAxisMaxValue='%d' numberPrefix='CH'>\n",CHANNEL_MAX_2G);
	}
	else if(mode == 5){
		printf("<chart palette='1' caption='无线网络分布' subcaption='AP分布图' bgColor='E7F0F9' "
			"showBorder='0' yAxisName='Channel' xAxisName='Signal' showLegend='1' showNames='1' "
			"xAxisMaxValue='100' xAxisMinValue='10' yAxisMaxValue='%d' numberPrefix='CH'>\n",channel_5g[CHANNEL_5G_NUM-1]);
	}
	else{
		return 0;
	}

	printf("<categories verticalLineColor='AA6666' verticalLineThickness='1'>\n");
	printf("<category name='-100dBm' x='100' showVerticalLine='1' /> \n");
	printf("<category name='-90dBm' x='90' showVerticalLine='1' /> \n");
	printf("<category name='-80dBm' x='80' showVerticalLine='1' /> \n");
	printf("<category name='-70dBm' x='70' showVerticalLine='1' /> \n");
	printf("<category name='-60dBm' x='60' showVerticalLine='1' /> \n");
	printf("<category name='-50dBm' x='50' showVerticalLine='1' /> \n");
	printf("<category name='-40dBm' x='40' showVerticalLine='1' /> \n");
	printf("<category name='-30dBm' x='30' showVerticalLine='1' /> \n");
	printf("<category name='-20dBm' x='20' showVerticalLine='1' /> \n");
	printf("<category name='-10dBm' x='10' showVerticalLine='0' /> \n");
	printf("</categories>\n");

	if(2 == mode){	
		for(i = 1; i < CHANNEL_MAX_2G+1; i++) {
			printf("<dataSet id='CH%d' seriesName='CH%d' plotBorderThickness='0' showPlotBorder='1' anchorSides='20' anchorRadius='2' anchorBorderThickness='4' anchorAlpha='75'>\n", i, i);
			wips_draw_scatter_by_channel(ap_list, i, 2);
			printf("</dataSet>\n");
		}
	}
	else if ( 5 == mode){
		for(i = 0; i<CHANNEL_5G_NUM; i++){
			printf("<dataSet id='CH%d' seriesName='CH%d' plotBorderThickness='0' showPlotBorder='1' anchorSides='20' anchorRadius='2' anchorBorderThickness='4' anchorAlpha='75'>\n", channel_5g[i], channel_5g[i]);
			wips_draw_scatter_by_channel(ap_list, i, 5);
			printf("</dataSet>\n");
		}
	}

	printf("<vTrendLines>");
		printf("<line startValue='100' endValue='80' displayValue='Poor' isTrendZone='1' color='FF0000' alpha='5' /> ");
		printf("<line startValue='80' endValue='50' displayValue='Normal' isTrendZone='1' color='5B5B00' alpha='5' /> ");
		printf("<line startValue='50' endValue='10' displayValue='Strong' isTrendZone='1' color='009900' alpha='5' /> ");
	printf("</vTrendLines>");

	printf("</chart>\n");

	free(ap_list);
	return 0;
}


int wips_get_radar_total_2G(void)
{
	int width,height,i,ch;
	float txpower[CHANNEL_MAX_2G],dbm = 0;
	char *ap_list;
	struct w_node *ap;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	for(i=0; i<CHANNEL_MAX_2G; i++)
		txpower[i] = 0;

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);

	for(i = 0; i < all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
		ch = convert_ap_channel(ap->channel);

		if(ch > 0 && ch <= CHANNEL_MAX_2G && ap->freq_band == 2) {
			txpower[ch-1] += pow(10.0, (float)ap->signal/10.0);
		}
	}


	printf("<chart caption='无线信道状态' anchorAlpha='0' bgColor='E7F0F9' showBorder='0' unescapeLinks='0'>\n");
	printf("<categories>\n");

	for(i=1; i<=CHANNEL_MAX_2G; i++)
		printf("<category label='Channel %d' />\n",i);
	
	printf("</categories>\n");
	printf("<dataset seriesName='信号强度分布'>\n");

	for(i = 0; i < CHANNEL_MAX_2G; i++) {
		if(txpower[i] > 0)
			dbm = log10(txpower[i]) * 10.0;
		else
			dbm = -96.0;

		printf("<set value='%d' />\n", (int)dbm);
	}

	printf("</dataset>\n");
	printf("</chart> \n");

	free(ap_list);
	return 0;
}


int wips_get_radar_total_5G(void)
{
	int i,ch,j;
	float txpower[CHANNEL_5G_NUM],dbm = 0;
	char *ap_list;
	struct w_node *ap;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	for(i=0; i<CHANNEL_5G_NUM; i++)
		txpower[i] = 0;

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);

	for(i = 0; i < all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
		ch = convert_ap_channel(ap->channel);

		j=0;
		while(j<CHANNEL_5G_NUM){
			if(ch == channel_5g[j] && ap->freq_band == 5){
				txpower[j] += pow(10.0, (float)ap->signal/10.0);
				break;
			}
			j++;
		}
	}

	printf("<chart caption='无线信道状态' anchorAlpha='0' bgColor='E7F0F9' showBorder='0' unescapeLinks='0'>\n");
	printf("<categories>\n");
	
	for(i=0; i<CHANNEL_5G_NUM; i++)
		printf("<category label='Ch %d' />\n",channel_5g[i]);

	printf("</categories>\n");
	printf("<dataset seriesName='信号强度分布'>\n");

	for(i = 0; i < CHANNEL_5G_NUM; i++) {
		if(txpower[i] > 0)
			dbm = log10(txpower[i]) * 10.0;
		else
			dbm = -96.0;

		printf("<set value='%d' />\n", (int)dbm);
	}

	printf("</dataset>\n");
	printf("</chart> \n");

	free(ap_list);
	return 0;
}




int ap_detail_old(void)
{
	int i;
	char *ap_list;
	char mac[24];
	char *tm1, *tm2, *we;
	struct w_node *ap;

	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		return 0;
	}

	all_ap_num =  *((int *)(ap_list));
	all_ap_num = all_ap_num/sizeof(struct w_node);

	printf("{success:true, total:16, data:[\n");

	for(i = 1; i < all_ap_num; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);

		if(strncmp(name, &mac[0], 17) == 0) {
			time2string(ap->up_time, &tm1);
			time2string(ap->last_time, &tm2);

			get_wevent_buf_by_wnode(ap);
			we = &wevent_buf[0];

			get_stats_ssid(ap);
			printf("{key:\"<span style='font-weight:bold;'>Name</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Type</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>SSID</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>IP</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>MAC</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Channel</span>\", value:\"%d MHz\"},\n"
				"{key:\"<span style='font-weight:bold;'>Security</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Interval</span>\", value:\"%d ms\"},\n"
				"{key:\"<span style='font-weight:bold;'>Mode</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Signal</span>\", value:\"%d dBm\"},\n"
				"{key:\"<span style='font-weight:bold;'>Noise</span>\", value:\"%d dBm\"},\n"
				"{key:\"<span style='font-weight:bold;'>UpTime</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>LastTime</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Vendor</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Permit</span>\", value:\"%d\"},\n"
				"{key:\"<span style='font-weight:bold;'>Alert</span>\", value:\"%s\"}",
				"", "",(char *)P(stats_ssid),(char *)P(ap->ipv4), mac, ap->channel, ap->sec_type, ap->interval,
				(char *)P(convert_ap_mode(ap->g_rates,ap->n_rates)), ap->signal, ap->noise,
				(char *)P(tm1),(char *)P(tm2),(char *)P(ap->vendor),ap->block, (char *)P(we));

			free(tm1);
			free(tm2);
			wevent_buf[0] = '\0';
			break;
		}
	}


	printf("]}\n");

	free(ap_list);
	return 0;
}

int ap_detail(void)
{
	char *ap_list;
	char mac[24], cmd[64];
	char *tm1, *tm2, *we;
	struct w_node *ap;

	sprintf(&cmd[0], "wnode%s", name);
	ap_list = get_wips_data((char *)&cmd[0]);
	if(ap_list == NULL) {
        printf("get ap_detail failed, mac:%s\n",name);
		return 0;
	}

	printf("{success:true, total:16, data:[\n");

	ap = (struct w_node *)(ap_list + sizeof(int));
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		ap->mac[0],ap->mac[1],ap->mac[2],ap->mac[3],ap->mac[4],ap->mac[5]);

	time2string(ap->up_time, &tm1);
	time2string(ap->last_time, &tm2);

	get_wevent_buf_by_wnode(ap);
	we = &wevent_buf[0];

	get_stats_ssid(ap);
	deal_ssid((char *)&stats_ssid[0]);
	if(ap->channel > 2000)
		printf("{key:\"<span style='font-weight:bold;'>Name</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Type</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>SSID</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>IP</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>MAC</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Channel</span>\", value:\"%d MHz\"},\n"
		"{key:\"<span style='font-weight:bold;'>Security</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Interval</span>\", value:\"%d ms\"},\n"
		"{key:\"<span style='font-weight:bold;'>Mode</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Signal</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>Noise</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>UpTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>LastTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Vendor</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Permit</span>\", value:\"%d\"},\n"
		"{key:\"<span style='font-weight:bold;'>Alert</span>\", value:\"%s\"}",
		"", "",(char *)P(stats_ssid),(char *)P(ap->ipv4), mac, ap->channel, ap->sec_type, ap->interval,
		(char *)P(convert_ap_mode(ap->g_rates,ap->n_rates)), ap->signal, ap->noise,
		(char *)P(tm1),(char *)P(tm2),(char *)P(ap->vendor),ap->block, (char *)P(we));
	else
		printf("{key:\"<span style='font-weight:bold;'>Name</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Type</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>SSID</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>IP</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>MAC</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Channel</span>\", value:\"%d\"},\n"
		"{key:\"<span style='font-weight:bold;'>Security</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Interval</span>\", value:\"%d ms\"},\n"
		"{key:\"<span style='font-weight:bold;'>Mode</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Signal</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>Noise</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>UpTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>LastTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Vendor</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Permit</span>\", value:\"%d\"},\n"
		"{key:\"<span style='font-weight:bold;'>Alert</span>\", value:\"%s\"}",
		"", "",(char *)P(stats_ssid),(char *)P(ap->ipv4), mac, ap->channel, ap->sec_type, ap->interval,
		(char *)P(convert_ap_mode(ap->g_rates,ap->n_rates)), ap->signal, ap->noise,
		(char *)P(tm1),(char *)P(tm2),(char *)P(ap->vendor),ap->block, (char *)P(we));


	printf("]}\n");

	free(tm1);
	free(tm2);
	free(ap_list);

	wevent_buf[0] = '\0';
	return 0;
}




int sta_detail_old(void)
{
	int i;
	char *sta_list;
	char mac[24],bssid[24];
	char *tm1, *tm2, *we;
	struct w_node *sta;

	sta_list = get_wips_data("stalist");
	if(sta_list == NULL) {
		return 0;
	}

	all_sta_num =  *((int *)(sta_list));
	all_sta_num = all_sta_num/sizeof(struct w_node);

	printf("{success:true, total:12, data:[\n");

	for(i = 1; i < all_sta_num; i++) {
		sta = (struct w_node *)(sta_list + sizeof(int) + i*sizeof(struct w_node));

		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5]);
		sprintf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x",
			sta->bssid[0],sta->bssid[1],sta->bssid[2],sta->bssid[3],sta->bssid[4],sta->bssid[5]);
//printf("%s-%s\n", mac, bssid);
		if(strncmp(name, &mac[0], 17) == 0) {
			time2string(sta->up_time, &tm1);
			time2string(sta->last_time, &tm2);
			get_wevent_buf_by_wnode(sta);
			we = &wevent_buf[0];

			printf("{key:\"<span style='font-weight:bold;'>IP</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>MAC</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>BSSID</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Channel</span>\", value:\"%d MHz\"},\n"
				"{key:\"<span style='font-weight:bold;'>Rates</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Signal</span>\", value:\"%d dBm\"},\n"
				"{key:\"<span style='font-weight:bold;'>Noise</span>\", value:\"%d dBm\"},\n"
				"{key:\"<span style='font-weight:bold;'>UpTime</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>LastTime</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Vendor</span>\", value:\"%s\"},\n"
				"{key:\"<span style='font-weight:bold;'>OS</span>\", value:\"%s %s\"},\n"
				"{key:\"<span style='font-weight:bold;'>Alert</span>\", value:\"%s\"}",
				(char *)P(sta->ipv4),mac, bssid, sta->channel, (char *)P(convert_sta_rate(sta->rates)), sta->signal,sta->noise,
				(char *)P(tm1),(char *)P(tm2), (char *)P(sta->vendor),"", "", (char *)P(we));

			free(tm1);
			free(tm2);
			wevent_buf[0] = '\0';
			break;
		}
	}

	printf("]}\n");

	free(sta_list);
	return 0;
}


int sta_detail(void)
{
	char *sta_list;
	char mac[24],bssid[24], cmd[64];
	char *tm1, *tm2, *we;
	struct w_node *sta;

	sprintf(&cmd[0], "wnode%s", name);
	sta_list = get_wips_data((char *)&cmd);
	if(sta_list == NULL) {
		return 0;
	}

	printf("{success:true, total:12, data:[\n");

	sta = (struct w_node *)(sta_list + sizeof(int));

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		sta->mac[0],sta->mac[1],sta->mac[2],sta->mac[3],sta->mac[4],sta->mac[5]);
	sprintf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x",
		sta->bssid[0],sta->bssid[1],sta->bssid[2],sta->bssid[3],sta->bssid[4],sta->bssid[5]);
//printf("%s-%s\n", mac, bssid);

	time2string(sta->up_time, &tm1);
	time2string(sta->last_time, &tm2);
	get_wevent_buf_by_wnode(sta);
	we = &wevent_buf[0];

	if(sta->channel > 2000)
		printf("{key:\"<span style='font-weight:bold;'>IP</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>MAC</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>BSSID</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Channel</span>\", value:\"%d MHz\"},\n"
		"{key:\"<span style='font-weight:bold;'>Rates</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Signal</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>Noise</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>UpTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>LastTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Vendor</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>OS</span>\", value:\"%s %s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Alert</span>\", value:\"%s\"}",
		(char *)P(sta->ipv4),mac, bssid, sta->channel, (char *)P(convert_sta_rate(sta->rates)), sta->signal,sta->noise,
		(char *)P(tm1),(char *)P(tm2), (char *)P(sta->vendor),"", "", (char *)P(we));
	else
		printf("{key:\"<span style='font-weight:bold;'>IP</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>MAC</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>BSSID</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Channel</span>\", value:\"%d\"},\n"
		"{key:\"<span style='font-weight:bold;'>Rates</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Signal</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>Noise</span>\", value:\"%d dBm\"},\n"
		"{key:\"<span style='font-weight:bold;'>UpTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>LastTime</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Vendor</span>\", value:\"%s\"},\n"
		"{key:\"<span style='font-weight:bold;'>OS</span>\", value:\"%s %s\"},\n"
		"{key:\"<span style='font-weight:bold;'>Alert</span>\", value:\"%s\"}",
		(char *)P(sta->ipv4),mac, bssid, sta->channel, (char *)P(convert_sta_rate(sta->rates)), sta->signal,sta->noise,
		(char *)P(tm1),(char *)P(tm2), (char *)P(sta->vendor),"", "", (char *)P(we));



	printf("]}\n");

	free(tm1);
	free(tm2);
	free(sta_list);

	wevent_buf[0] = '\0';
	return 0;
}

int wips_get_cur_ch_2g(void)
{
	int i, j, all, sum, num[CHANNEL_MAX_2G+1];
	char *ap_list;
	struct w_node *ap;

	sum=0;
	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		all = 0;
	}
	else {
	all =  *((int *)(ap_list));
	all = all/sizeof(struct w_node);
	}

	for(j = 0; j < CHANNEL_MAX_2G; j++)
		num[j] = 0;

	for(i = 0; i < all; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));

		for(j = 1; j < CHANNEL_MAX_2G +1; j++) {
			if(ap->channel > 2000) {
				//if(convert_ap_channel(ap->channel) == j){
				if(convert_ap_channel(ap->channel) == j && ap->freq_band == 2){	
					num[j-1]++;
					sum++;
					}
				//else printf("freq_band:%d;channel:%d\n",ap->freq_band,convert_ap_channel(ap->channel));
			}
			else {
				//if(ap->channel == j){
				if(ap->channel == j && ap->freq_band == 2){
					num[j-1]++;
					sum++;
					}
				//else printf("freq_band:%d;channel:%d\n",ap->freq_band,convert_ap_channel(ap->channel));
			}

		}
	}


	printf("<graph caption='无线接入点分布(2.4G)' subcaption='总数 %d' animation ='0' showShadow='1' "
		"plotFillRatio='100' bgColor='E7F0F9' showBorder='0' ", sum);
	printf("decimalPrecision=\"2\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"bgColor=\"E7F0F9\" canvasBgColor='E7F0F9' canvasBaseColor='E7F0F9' outCnvBaseFontSize=\"12\" yAxisName=\"num\" ");
	printf("useRoundEdges='1' showAreaBorder='0' areaAlpha='100' numVDivLines='20' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBorderColor='E7F0F9' canvasBorderThickness='1' >\n");


	printf_style();

	for (i = 1; i < CHANNEL_MAX_2G+1; i++) {
		printf("<set name='信道%d' value='%d' tooltext='信道 %d\n无线接入点数量 %d' />\n",
			i, num[i-1], i, num[i-1]);
	}

	printf("</graph>\n");

	free(ap_list);

	return 0;
}

int wips_get_cur_ch_5g(void)
{
	int i, j, all,sum,num[CHANNEL_5G_NUM];
	char *ap_list;
	struct w_node *ap;

	sum=0;
	ap_list = get_wips_data("aplist");
	if(ap_list == NULL) {
		all = 0;
	}
	else {
	all =  *((int *)(ap_list));
	all = all/sizeof(struct w_node);
	}

	for(j = 0; j < CHANNEL_5G_NUM; j++)
		num[j] = 0;

	for(i = 0; i < all; i++) {
		ap = (struct w_node *)(ap_list + sizeof(int) + i*sizeof(struct w_node));

		for(j = 0; j < CHANNEL_5G_NUM; j++) {
			if(ap->channel > 2000) {
				//if(convert_ap_channel(ap->channel) == channel_5g[j]){
				if(convert_ap_channel(ap->channel) == channel_5g[j] && ap->freq_band == 5){
					num[j]++;
					sum++;
					}				
			}
			else {
				//if(ap->channel == channel_5g[j]){
				if(ap->channel == channel_5g[j] && ap->freq_band == 5){
					num[j]++;
					sum++;
					}
			}

		}
	}


	printf("<graph caption='无线接入点分布(5G)' subcaption='总数 %d' animation ='0' showShadow='1' "
		"plotFillRatio='100' bgColor='E7F0F9' showBorder='0' ", sum);
	printf("decimalPrecision=\"2\" baseFontSize=\"12\" formatNumberScale=\"1\"  exportEnabled=\"0\" "
		"bgColor=\"E7F0F9\" canvasBgColor='E7F0F9' canvasBaseColor='E7F0F9' outCnvBaseFontSize=\"8\" yAxisName=\"num\" ");
	printf("useRoundEdges='1' showAreaBorder='0' areaAlpha='100' numVDivLines='20' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBorderColor='E7F0F9' canvasBorderThickness='1' >\n");


	printf_style();

	for (i = 0; i < CHANNEL_5G_NUM; i++) {
		printf("<set name='%d' value='%d' tooltext='信道 %d\n无线接入点数量 %d' />\n",
			channel_5g[i], num[i], channel_5g[i], num[i]);
	}

	printf("</graph>\n");

	free(ap_list);

	return 0;
}



int get_wnode_data(const char *cmd, char *getbuf,int buflen)
{
	int cfd,len;
	char cmd1[64];
	struct sockaddr_un un;
	struct timeval recv_timeval;

	recv_timeval.tv_sec = 2;
	recv_timeval.tv_usec =0;

	if(!cmd)
		return -1;

	if((strncmp(cmd, "get_ap_num", 10)!=0)&& (strncmp(cmd, "get_start_flag", 14)!=0)) {
		printf("get_wipsd_data cmd is error!\n");
		printf("cmd:\n get_ap_num or get_start_flag \n");
		return -1;
	}

	bzero((char *)cmd1, sizeof(cmd1));
	strncpy(cmd1, cmd , sizeof(cmd1));

	if((cfd=socket(AF_UNIX,SOCK_STREAM,0))==-1){
		perror("Fail to socket");
		return -1;
	}
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeval, sizeof(recv_timeval));

#if 1
	memset(&un,0,sizeof(struct sockaddr_un));
	un.sun_family=AF_UNIX;
	sprintf(un.sun_path,"%s%d",C_PATH,getpid());
	len=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	unlink(un.sun_path);

	if(bind(cfd,(struct sockaddr *)&un,len)==-1){
		perror("Fail to bind");
		return  -1;
	}


	if(chmod(un.sun_path,S_IRWXU)<0){
		perror("Fail to chmod");
		return -1;
	}
#endif

	memset(&un,0,sizeof(struct sockaddr_un));
	un.sun_family=AF_UNIX;
	strcpy(un.sun_path,PATH);

	len=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	if(connect(cfd,(struct sockaddr *)&un,len)<0){
		perror("Fail to connect\n");
		return -1;
	}

	if(write(cfd, cmd1, sizeof(cmd1))==-1){
		perror("Fail to write\n");
		close(cfd);
		return -1;
	}

	if((len = read(cfd, (char *)getbuf, buflen)) != buflen)
	{
		perror("read");
		close(cfd);
		return -1;
	}
	close(cfd);
	return 0;
}
int wnode_num_hour_online()
{
	return 0;
}
int wnode_num_online(void)
{
	int fd = open("/usr/hls/log/stats/ap", O_RDONLY);
	void *map;
	struct save_elem_wnode *elem;
	struct save_head *head;
	int index, i, step, count;
	struct tm *timenow;
	time_t now = time(NULL);
	int *counts;
	struct save_elem_wnode getbuf;
	int buflen, ret, ru = 3;

	if (strcmp(period_str, "10分钟") == 0)
		return wnode_num_hour_online();
	else if(strcmp(period_str, "天") == 0)
		ru = 3;			//24*6
	else if(strcmp(period_str, "周") == 0)
		ru = 14;			//24*6*7
	else if(strcmp(period_str, "月") == 0)
//		ru = 30;			//24*6*30
		ru = 1;

	step = period / 24 / ru;
	if(!fd) {
		perror("session_online touch global log failed. \n");
		return 0;
	}

	buflen = 0;
	#if 0
	ret = gen_get_stats(STATS_TYPE_TNODE_CURRENT, 0, NULL, &buf, &buflen);
	if (ret < 0) {
		error("ioctl get tnode current stats failed. errno=%d\n", errno);
		return 0;
	}
	#endif

	#if 0
	ret = get_wnode_data("get_start_flag",(char *)&start_flag, sizeof(int));
	if(ret < 0){
		error("ioctl get tnode current stats failed. errno=%d\n", errno);
		return 0;
	}
	#endif

	//printf("start_flag = %d \n", start_flag);
	ret = get_wnode_data("get_ap_num",(char *)&getbuf, sizeof(struct save_elem_wnode));
	if(ret < 0){
		printf("ioctl get tnode current stats failed. errno=%d\n", errno);
		return 0;
	}
	counts = (int *)&getbuf;

	map = mmap(0, sizeof(struct save_head) + sizeof(struct save_elem_wnode) *APP_SAVE_SIZE, PROT_READ, MAP_SHARED, fd, 0);


	head = (struct save_head *)map;
	elem = (struct save_elem_wnode *)(head + 1);


	index = (head->index - period + 1 + APP_SAVE_SIZE) % APP_SAVE_SIZE;


	printf("<chart caption=\"%s  周期(%s)\" animation ='0' rotateNames='0' slantLabels='1'  drawAnchors='0' showValues=\"0\" baseFontSize=\"12\" labelStep=\"%d\" "
		"decimalPrecision=\"1\" formatNumberScale=\"1\"  exportEnabled=\"1\" bgColor=\"E7F0F9\" "
		"showBorder='0' outCnvBaseFont=\"Arial\" outCnvBaseFontSize=\"12\" yAxisName=\"设备数量\" ", "设备趋势", period_str, step);

	printf("numVDivLines='%d' divlinecolor='cccccc' vDivlinecolor='cccccc' canvasBgColor='E7F0F9' canvasBorderColor='E7F0F9' canvasBorderThickness='1' >\n",20);

	printf("<categories>\n");

	for (i = index, count = 0; count < period; i+=ru, count+=ru) {
		if (i == APP_SAVE_SIZE)
			i = 0;

		now = head->timestamp - APP_SAVE_INTVAL*(period - count - 0);
		timenow = localtime(&now);

		if (period > 25*6)
			printf("<category label=\"%d-%d\"/>\n",
				timenow->tm_mon+1, timenow->tm_mday);
		else
			printf("<category label=\"%02d:%02d\"/>\n", timenow->tm_hour, timenow->tm_min);

	}

	now = time(NULL);
	timenow = localtime(&now);

	if (period > 25*6)
		printf("<category label=\"%d-%d\"/>\n",
			timenow->tm_mon+1, timenow->tm_mday);
	else
		printf("<category label=\"%02d:%02d\"/>\n", timenow->tm_hour, timenow->tm_min);

	printf("</categories>\n");


	printf("<dataset seriesName=\"AP 数量\" color=\"0080C0\" anchorBorderColor=\"0080C0\" anchorBgColor=\"0080C0\">\n");

	for (i = index, count = 0; count < period; i+=ru, count+=ru) {
		if (i >= APP_SAVE_SIZE)
			i = 0;
		//printf("i=%d \n",i);
		printf("<set value=\"%u\"/>\n", elem[i].ap_num);
	}

	if(start_flag){
		printf("<set value=\"%u\"/>\n", elem[i].ap_num);
		}
	else
		printf("<set value=\"%u\"/>\n", counts[0]);
	printf("</dataset>\n");

       printf("<dataset seriesName=\"STATION 数量\" color=\"ff0000\" anchorBorderColor=\"0080C0\" anchorBgColor=\"0080C0\">\n");
	//printf("<set value=\"%d\"/>\n", elem[0].cps);

	for (i = index, count = 0; count < period; i+=ru, count+=ru) {
		if (i >= APP_SAVE_SIZE)
			i = 0;
		printf("<set value=\"%d\"/>\n", elem[i].station_num);
	}
	//printf current staion num value
	if(start_flag)
		printf("<set value=\"%d\"/>\n", elem[i].station_num);
	else
		printf("<set value=\"%u\"/>\n", counts[1]);
	printf("</dataset>\n");


	//printf("<trendLines>\n");
	//printf("<line startValue='%u' color='ff0000' displayvalue='当前会话数' toolText='当前会话数: %u' />\n", counts[0], counts[0]);
	//printf("</trendLines>\n");

	printf("</chart>\n");
	munmap(map, sizeof(struct save_head) + sizeof(struct save_elem_wnode) *APP_SAVE_SIZE);
	return 0;
}

int main(int argc, char **argv)
{
	int i,w,h;

	if(argc < 3)
		return 0;

	for (i = 1; i < argc; i++) {
	  	DR(0, 2, "arg[%d]=%s", i, argv[i]);
		if (strcmp(argv[i], "type") == 0)
			type = strdup(argv[++i]);
		else if (strcmp(argv[i], "id") == 0)
			id = (unsigned int)atoll(argv[++i]);
		else if (strcmp(argv[i], "top") == 0)
			topN = atoi(argv[++i]);
		else if (strcmp(argv[i], "start") == 0)
			start = atoi(argv[++i]);
		else if (strcmp(argv[i], "limit") == 0)
			limit = atoi(argv[++i]) == 0?limit:atoi(argv[i]);
		else if (strcmp(argv[i], "name") == 0)
			name = strdup(argv[++i]);
		else if (strcmp(argv[i], "period") == 0) {
			char *p = strdup(argv[++i]);

			if (strcmp(p, "day") == 0) {
				period_str = "天";
				period = 24*6;
			} else if (strcmp(p, "week") == 0) {
				period_str = "周";
				period = 24*6*7;
			} else if (strcmp(p, "month") == 0) {
				period_str = "月";
				period = 24*6*28;
			} else {
				period_str = "10分钟";
				period = 10*6;

			}
		}
		else if (strcmp(argv[i], "width") == 0) {
			w= atoi(argv[++i]);
			if(w > 0)
				pgWidth = w;
		}
		else if (strcmp(argv[i], "height") == 0) {
			h= atoi(argv[++i]);
			if(h > 0)
				pgHeight = h;
		}
		DR(0, 2, "arg[%d]=%s", i, argv[i]);
	}


	if (strcmp(type, "rf") == 0)
		rf_vled_gauge();
	else if (strcmp(type, "sonar") == 0)
		wips_sonar_scan();
	else if (strcmp(type, "wipsWirelessTopoTotal") == 0)
		wips_get_topology_total();
	else if (strcmp(type, "wipsWirelessScatterTotal_2G") == 0)
		wips_get_scatter_total(2);
	else if (strcmp(type, "wipsWirelessScatterTotal_5G") == 0)
		wips_get_scatter_total(5);
	else if (strcmp(type, "wipsWirelessRadarTotal_2G") == 0)
		wips_get_radar_total_2G();
	else if (strcmp(type, "wipsWirelessRadarTotal_5G") == 0)
		wips_get_radar_total_5G();
	else if (strcmp(type, "apDetail") == 0)
		ap_detail();
	else if (strcmp(type, "staDetail") == 0)
		sta_detail();
	else if (strcmp(type, "wipsGetWlist") == 0)
		wips_get_wireless_list();
	else if (strcmp(type, "wipsGetWssid") == 0)
        wips_get_wireless_list_ssid();
	else if (strcmp(type, "wipsGetWchannel") == 0)
        wips_get_wireless_list_channel();
	else if (strcmp(type, "wipsAttackStats") == 0)
		wips_attack_list();
	else if (strcmp(type, "wips2gChannelCur") == 0)
		wips_get_cur_ch_2g();
	else if (strcmp(type, "wips5gChannelCur") == 0)
		wips_get_cur_ch_5g();
	else if (strcmp(type, "wipsAttackColumnCur") == 0)
		wips_attack_column_cur();
	else if (strcmp(type, "wipsAttackColumnTotal") == 0)
		wips_attack_column_total();
	else if (strcmp(type, "wipsAttackPieCur") == 0)
		wips_attack_pie_cur();
	else if (strcmp(type, "wipsAttackPieTotal") == 0)
		wips_attack_pie_total();
	else if (strcmp(type, "wipsAttackFunnelTotal") == 0)
		wips_attack_funnel_total();
	else if (strcmp(type, "print_bt") == 0)
		wips_print_block_table();
	else if (strcmp(type, "wnodeNumOnline") == 0)
		wnode_num_online();
	
	if(type)
		free(type);
	if(name)
		free(name);

	return 0;

}
#endif

