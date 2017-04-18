#include <zebra.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/wait.h>
#include "zthread_support.h"
#include "if_support.h"
#include "io_support.h"
#include "fs_support.h"
#include "thread.h"
#include "if.h"
#include "getopt.h"
#include "memory.h"
#include "message.h"
#include "vty.h"
#include "zclient.h"
#include "list.h"
#include "../vtysh/vtysh.h"
#include "wipsd_wnode.h"
#include "wipsd.h"
#include "sqlite3.h"
#include "wipsd_hook.h"
#include "subnet_hash.h"
#include "wgate_hash.h"
#include "dobj_wgate.h"
#include "wipsd_interface.h"
#include "wipsd_sql.h"
#include "wipsd_policy.h"
#include "../../../kernel/include/linux/netfilter_ipv4/fw_objects.h"


extern struct thread_master *master;
extern struct zclient *zclient;
extern struct wipsd_interface_hdr *wipsd_itf_list;
extern int packet_counter;
extern int packet_counter4show;
extern int wireless_node_age;
extern long fresh_time;
extern int wpolicy_update_tag;
extern sqlite3 *sql_wconfig;
extern wpolicy_struct		*wpolicy_list;
extern int wpolicy_index;
extern int wpolicy_num;
extern int suspend_package_num;
extern int packet_syslog_out;

int check_wlist_time=0;
struct ztimer wips_update_timer;

extern void wipsd_init_vty(void);
extern int wipsd_handle_wlansniffrm(u8 *buf, int len, struct wipsd_interface *wipsd_itf, struct sockaddr_in *addr);
extern void task_stack(void);
extern int get_wlist_node(char * mac, struct w_node ** node_frame);

void update_wpolicy_list(int init);
int wipsd_open_interface_sock(struct interface *itf, u32 ip, u16 port);

char *find_mac_vendor(char *mac);






#define str_len 8192

int get_encrypt_algorithm_type(char* type)
{
	if(strstr(type,"wep"))
	return 1;
	if(strstr(type,"wpa2"))
	return 3;
	if(strstr(type,"wpa"))
	return 2;
	if(strstr(type,"psk"))
	return 4;

	return 99;
	}
	#define COORDINATE 0
#if 0
char* get_char_from_mmap(char* file_mem,char* str)
{
	char* tmp=NULL;
	tmp=strstr(file_mem,str);
	if(NULL==tmp)
	{
		vty_print_std("can't find str:%s\n",str);

		return NULL;
	}else
	return tmp+(strlen(str));
	
}

int send_base_table_to_logserver(char* file_mem,char* table_name)
{
	char code[32];
	char code_name[128];
	char code_val[256];
	char str[str_len];
	char str_tmp[1024];

	memset(str_tmp,0,1024);
	memset(str,0,str_len);
	memset(code_val,0,256);
	memset(code_name,0,128);
	memset(code,0,32);
	if(file_mem == NULL)
	return -1;

	
	char *p=strstr(file_mem,table_name);

	if(p==NULL)
	{
		vty_print_std("can't find str %s  in file\n",table_name);
		return -1;
		}
//	sscanf(p,"%s",table_name);
	sprintf(str_tmp,"TABLE_NAME=\"%s\"",table_name);
	strcat(str,str_tmp);
	for(;;)
	{
		p=strchr(p,'\n');
		if(p==NULL)
		{
			break;
		}
		p++;
		if('#'==*p)
		{
			break;
		}
		memset(code_val,0,256);
		memset(code_name,0,128);
		memset(code,0,32);
		if(3 != sscanf(p,"%s %s %s",code,code_name,code_val))
		continue;

		sprintf(str_tmp," #%s(%s)=\"%s\"",code,code_name,code_val);
		strcat(str,str_tmp);
		}

		
			vsos_syslog_2(MODULE_ACD, 0,"%s\n",str);
		return 0;


}
int send_base_info_to_logserver(char* filename)
{
	  char *memory = NULL;
	  int file_length = 0;
	  char *start_address = 0;

	  int fd = open(filename, O_RDONLY );
	  if ( fd > 0 )
	    {
	      file_length = lseek(fd, 1, SEEK_END);
	      memory = mmap( start_address, file_length, PROT_READ, MAP_SHARED, fd, 0 );
		
	    }else{
	    	vty_print_std("open file %s\n",filename);
	    	return -1;
		}

		send_base_table_to_logserver(memory,"WA_BASIC_FJ_1002");
		send_base_table_to_logserver(memory,"WA_BASIC_FJ_1003");
		send_base_table_to_logserver(memory,"WA_BASIC_FJ_1004");
		close( fd );
 			munmap( memory, file_length );
 			return 0;
     			
}
	

int syslogd_save_log_timer(struct thread *th)
{

	char temp[64];
	  /*
	  int ret =0;
	
	  ret = system("ping 172.16.0.100 -c 1");
	  if(ret >= 0)
	  {
	  	a100=WEXITSTATUS(ret);
	  	}

	  ret= system("ping 172.16.0.101 -c 1");
	  if(ret >=0)
	  {
	  a101=WEXITSTATUS(ret);
	  }
	  
	  */
	  char* p1=filename_all;
	  char* p2=filename_all;
//	    	vty_print_std("filename_all: %s\n",filename_all);
	for(;;)
	{
		memset(temp,0,64);
		
		p2=strchr(p1,'#');
		if(NULL == p2)
			break;
		memcpy(temp,p1,(p2-p1));
		temp[(p2-p1)]='\0';
		send_base_info_to_logserver(temp);
		p2++;
		p1=p2;
		}
		memset(filename_all,0,256);
		#if 0
	  	  char *memory = NULL;
	  int file_length = 0;
	  char *start_address = 0;


	  for(
	  if(a100 == 1)
	  {
		  int fd = open( "./mnt/172.16.1.100", O_RDONLY );
		  if ( fd > 0 )
		    {
		      file_length = lseek(fd, 1, SEEK_END);
		      memory = mmap( start_address, file_length, PROT_READ, MAP_SHARED, fd, 0 );
			
		    }else{
		    	thread_add_timer(master, syslogd_save_log_timer, NULL, 30);

		    	vty_print_std("open file %s\n",filename);
		    	a100=0;
		    	return -1;
			}

			send_base_table_to_logserver(memory,"WA_BASIC_FJ_1002");
			send_base_table_to_logserver(memory,"WA_BASIC_FJ_1003");
			send_base_table_to_logserver(memory,"WA_BASIC_FJ_1004");
			close( fd );
     			munmap( memory, file_length );
			a100=0;
			
	}
		if(a101 == 1)
		{
		  int fd = open( "./mnt/172.16.1.101", O_RDONLY );
		  if ( fd > 0 )
		    {
		      file_length = lseek(fd, 1, SEEK_END);
		      memory = mmap( start_address, file_length, PROT_READ, MAP_SHARED, fd, 0 );
			
		    }else{
		    	vty_print_std("open file %s\n",filename);
		    	thread_add_timer(master, syslogd_save_log_timer, NULL, 30);
		    	a101=0;

		    	return -1;
			}

			send_base_table_to_logserver(memory,"WA_BASIC_FJ_1002");
			send_base_table_to_logserver(memory,"WA_BASIC_FJ_1003");
			send_base_table_to_logserver(memory,"WA_BASIC_FJ_1004");
			close( fd );
  			munmap( memory, file_length );
			a101=0;
			
		}
	
	#endif
	
			 thread_add_timer(master, syslogd_save_log_timer, NULL, 30);

	return 0;
}

#endif

int send_WA_SOURCE_FJ_1001_to_logserver(struct w_node* node,char* file_mem)
{
	int sec=time(NULL);
	
/*get base info from fd

	char filed_code[32];
	char monitor_id[32];
	char F010018[32];
	char F010019[32];
	if(file_mem == NULL)
	{
		memset(filed_code,0,32);
		memset(monitor_id,0,32);
		memset(F010018,0,32);
		memset(F010019,0,32);
		}else{

	sscanf(get_char_from_mmap(file_mem,"NETBAR_WACODE"),"%s",filed_code);
	sscanf(get_char_from_mmap(file_mem,"COLLECTION_EQUIPMENT_ID"),"%s",monitor_id);
	sscanf(get_char_from_mmap(file_mem,"COLLECTION_EQUIPMENT_LONGITUDE"),"%s",F010018);
	sscanf(get_char_from_mmap(file_mem,"COLLECTION_EQUIPMENT_LATITUDE"),"%s",F010019);
	}*/
	/*
#if COORDINATE

	char str[str_len];
	memset(str,0,str_len);
	sec=time(NULL);
	sprintf(str,"TABLE_NAME=\"%s\""\
			"F030011\"AP_MAC\"=\""MACSTR"\""\
			"F030001\"AP_SSID\"=\"%s\""\
			"F030022\"AP_CHANNEL\"=\"%d\""\
			"B040025\"ENCRYPT_ALGORITHM_TYPE\"=%02d"\
			"H010014\"CAPTURE_TIME\"=%d"\
			"F030023\"AP_FIELD_STRENGTH\"=\"%d\""\
			"I070001\"X_COORDINATE\"=\"%s\""\
			"I070002\"Y_COORDINATE\"=\"%s\""\
			"G020004\"NETBAR_WACODE\"=\"%s\""\
			"I070011\"COLLECTION_EQUIPMENT_ID\"=\"%s\""\
			"F010018\"COLLECTION_EQUIPMENT_LONGITUDE\"=\"%s\""\
			"F010019\"COLLECTION_EQUIPMENT_LATITUDE\"=\"%s\"",\
			"WA_SOURCE_FJ_1001",\
			MAC2STR(node->mac),\
			node->ssid,\
			node->channel,\
			get_encrypt_algorithm_type(node->sec_type),\
			sec,\
			node->signal,\
			"no support",\
			"no support",\
			filed_code,\
			monitor_id,\
			F010018,\
			F010019);
#elif
*/
		char str[str_len];
	memset(str,0,str_len);
	sec=time(NULL);
	sprintf(str,"INFO_TYPE=\"%s\""\
			" #F030011(AP_MAC)=\""MACSTR"\""\
			" #F030001(AP_SSID)=\"%s\""\
			" #F030022(AP_CHANNEL)=\"%d\""\
			" #B040025(ENCRYPT_ALGORITHM_TYPE)=%02d"\
			" #H010014(CAPTURE_TIME)=%d"\
			" #F030023(AP_FIELD_STRENGT)=\"%d\""\
			" #FFFFFFF(PROBER_MAC)=\""MACSTR"\"",\
			"AP_INFO",\
			MAC2STR(node->mac),\
			node->ssid,\
			node->channel,\
			get_encrypt_algorithm_type(node->sec_type),\
			sec,\
			node->signal,\
			MAC2STR(node->prober_mac));
/*

			vsos_syslog_2(MODULE_ACD, 0,"F030011AP_MAC="MACSTR"\n",MAC2STR(node->mac));
			vsos_syslog_2(MODULE_ACD, 0,"F030001\"AP_SSID\"=\"%s\"",node->ssid);

			vsos_syslog_2(MODULE_ACD, 0,"F030022\"AP_CHANNEL\"=\"%d\"",node->channel);

			vsos_syslog_2(MODULE_ACD, 0,"B040025\"ENCRYPT_ALGORITHM_TYPE\"=%02d",get_encrypt_algorithm_type(node->sec_type));

			vsos_syslog_2(MODULE_ACD, 0,"H010014\"CAPTURE_TIME\"=%d",sec);

			vsos_syslog_2(MODULE_ACD, 0,"F030023\"AP_FIELD_STRENGTH\"=\"%d\"",node->signal);

			vsos_syslog_2(MODULE_ACD, 0,"G020004\"NETBAR_WACODE\"=\"%s\"",filed_code);

			vsos_syslog_2(MODULE_ACD, 0,"I070011\"COLLECTION_EQUIPMENT_ID\"=\"%s\"",monitor_id);

			vsos_syslog_2(MODULE_ACD, 0,"F010018\"COLLECTION_EQUIPMENT_LONGITUDE\"=\"%s\"",F010018);
			vsos_syslog_2(MODULE_ACD, 0,"F010019\"COLLECTION_EQUIPMENT_LATITUDE\"=\"%s\"",F010018);
			*/


//#endif
		//	vty_print_std("send WA_SOURCE_FJ_1001 to server strlen:%d\n",(int)strlen(str));

		//	vsos_syslog_2(MODULE_ACD,0,"send WA_SOURCE_FJ_1001 to server strlen:%d\n",(int)strlen(str));
			vsos_syslog_2(MODULE_ACD, 0,"%s\n",str);
			//vty_print_std("%s\n",str);

			return 0;
			
			


	}

	int send_WA_SOURCE_FJ_1002_to_logserver(struct w_node* node,char* file_mem)
{

	int sec=time(NULL);
/*

	char filed_code[32];
	char monitor_id[32];
	char F010018[32];
	char F010019[32];

		if(file_mem == NULL)
	{
		memset(filed_code,0,32);
		memset(monitor_id,0,32);
		memset(F010018,0,32);
		memset(F010019,0,32);
		}else{

	sscanf(get_char_from_mmap(file_mem,"NETBAR_WACODE"),"%s",filed_code);
	sscanf(get_char_from_mmap(file_mem,"COLLECTION_EQUIPMENT_ID"),"%s",monitor_id);
	sscanf(get_char_from_mmap(file_mem,"COLLECTION_EQUIPMENT_LONGITUDE"),"%s",F010018);
	sscanf(get_char_from_mmap(file_mem,"COLLECTION_EQUIPMENT_LATITUDE"),"%s",F010019);
	}



*/

	
	char* brand=NULL;
	char mac[32];
	sprintf(mac,MACSTR,MAC2STR(node->mac));
	brand=find_mac_vendor(mac);
/*
#if COORDINATE

	char str[str_len];
	memset(str,0,str_len);
	sec=time(NULL);
	sprintf(str,"TABLE_NAME=\"%s\""\
			"C040002\"MAC\"=\""MACSTR"\""\
			"C010002\"BRAND\"=\"%s\""\
			"F030021\"CACHE_SSID\"=\"%s\""\
			"H010014\"CAPTURE_TIME\"=%d"\
			"I070003\"TERMINAL_FIELD STRENGTH\"=\"%d\""\
			//"I070005\"IDENTIFICATION_TYPE\"=\"%d\""\ 
			"I070005\"SSID_POSITION\"=\"%s\""\
			"I070006\"ACCESS_AP_MAC\"=\""MACSTR"\""\
			"I070007\"ACCESS_AP_CHANNEL\"=\"%d\""\
			"I070008\"ACCESS_AP_ENCRYPTION_TYPE\"=\"%d\""\
			"I070001\"X_COORDINATE\"=\"%s\""\
			"I070002\"Y_COORDINATE\"=\"%s\""\
			"G020004\"NETBAR_WACODE\"=\"%s\""\
			"I070011\"COLLECTION_EQUIPMENT_ID\"=\"%s\""\
			"F010018\"COLLECTION_EQUIPMENT_LONGITUDE\"=\"%s\""\
			"F010019\"COLLECTION_EQUIPMENT_LATITUDE\"=\"%s\"",\
			"WA_SOURCE_FJ_1002",\
			MAC2STR(node->mac),\
			brand,\
			"",\
			sec,\
			node->signal,\
			node->ssid,\
			MAC2STR(node->bssid),\
			node->channel,\
			get_encrypt_algorithm_type(node->sec_type),\
			"unsupport",\
			"unsupport",\
			filed_code,\
			monitor_id,\
			F010018,\
			F010019);
	#elif
	*/
		struct w_node* node_ap;
		
		char str[str_len];
		memset(str,0,str_len);
		sec=time(NULL);

		if(0 == get_wlist_node((char *)&node->bssid[0], &node_ap)){

	sprintf(str,"INFO_TYPE=\"%s\""\
			" #C040002(MAC)=\""MACSTR"\""\
			" #C010002(BRAND)=\"%s\""\
			" #H010014(CAPTURE_TIME)=%d"\
			" #I070003(TERMINAL_FIELD STRENGTH)=\"%d\""\
/*			" #070005(IDENTIFICATION_TYPE\)=\"%d\""\ */
			" #I070005(SSID_POSITION)=\"%s\""\
			" #I070006(ACCESS_AP_MAC)=\""MACSTR"\""\
			" #I070007(ACCESS_AP_CHANNEL)=\"%d\""\
			" #I070008(ACCESS_AP_ENCRYPTION_TYPE)=\"%d\""\
			" #FFFFFFF(PROBER_MAC)=\""MACSTR"\"",\
			"STA_INFO",\
			MAC2STR(node->mac),\
			brand,\
			sec,\
			node->signal,\
			node_ap->ssid,\
			MAC2STR(node->bssid),\
			node->channel,\
			get_encrypt_algorithm_type(node->sec_type),\
			MAC2STR(node->prober_mac));

			}else{
	sprintf(str,"INFO_TYPE=\"%s\""\
			" #C040002(MAC)=\""MACSTR"\""\
			" #C010002(BRAND)=\"%s\""\
			" #H010014(CAPTURE_TIME)=%d"\
			" #I070003(TERMINAL_FIELD STRENGTH)=\"%d\""\
/*			" #070005(IDENTIFICATION_TYPE\)=\"%d\""\ */
			" #I070005(SSID_POSITION)=\"%s\""\
			" #I070006(ACCESS_AP_MAC)=\""MACSTR"\""\
			" #I070007(ACCESS_AP_CHANNEL)=\"%d\""\
/*			" #I070008(ACCESS_AP_ENCRYPTION_TYPE)=\"%d\""\*/
			" #FFFFFFF(PROBER_MAC)=\""MACSTR"\"",\
			"STA_INFO",\
			MAC2STR(node->mac),\
			brand,\
			sec,\
			node->signal,\
			node->ssid,\
			MAC2STR(node->bssid),\
			node->channel,\
/*			get_encrypt_algorithm_type(node->sec_type),\*/
			MAC2STR(node->prober_mac));
			}
//#endif
	//		vty_print_std("send WA_SOURCE_FJ_1002 to server strlen:%d\n",(int)strlen(str));

	//		vsos_syslog_2(MODULE_ACD,0,"send WA_SOURCE_FJ_1002 to serve strlen:%d\n",(int)strlen(str));
			vsos_syslog_2(MODULE_WIPS, 0,"%s\n",str);
			//vty_print_std("%s\n",str);
			return 0;
			
			


	}

void dump_wnode_2_term(struct w_node *node )
{
	vty_print_std("===========dump a wnode start==========\n");
	vty_print_std("|	alert-----------: 0x%08X%08X%08X%08X%08X\n", 
		node->alert[4], node->alert[3], 
		node->alert[2], node->alert[1], node->alert[0]);
	vty_print_std("|	up_time---------: %d\n", (int)node->up_time);
	vty_print_std("|	last_time-------: %d\n", (int)node->last_time);
	vty_print_std("|	refresh_time----: %d\n", (int)node->refresh_time);
	vty_print_std("|	beacon_c--------: %d\n", node->beacon_c);
//	vty_print_std("|	timestamp-------: 0x%"PRIX64"\n", node->timestamp);
	vty_print_std("|	ssidn_type------: %s\n", node->ssidn_type ? "sta":"ap");
	vty_print_std("|	capability_info-: %d\n", node->capability_info);
	vty_print_std("|	channel---------: %d\n", node->channel);
	vty_print_std("|	freq_band ------: %d\n", node->freq_band);
	vty_print_std("|	interval--------: %d\n", node->interval);
	vty_print_std("|	reason_code-----: %d\n", node->reason_code);
	vty_print_std("|	id--------------: %d\n", node->id);
	vty_print_std("|	block-----------: %d\n", node->block);
	vty_print_std("|	rates-----------: %d\n", node->rates);
	vty_print_std("|	duration--------: %d\n", node->duration);
	vty_print_std("|	sequence_num----: %d\n", node->sequence_num);
	vty_print_std("|	vendor----------: %s\n", node->vendor);
	vty_print_std("|	sec_type--------: %s\n", node->sec_type);
	vty_print_std("|	ipv4------------: %s\n", node->ipv4);
	vty_print_std("|	ssid------------: %s\n", node->ssid);
	vty_print_std("|	name------------: %s\n", node->name);
	vty_print_std("|	bssid-----------: "MACSTR"\n", MAC2STR(node->bssid));
	vty_print_std("|	mac-------------: "MACSTR"\n", MAC2STR(node->mac));
	vty_print_std("|	lan_mac---------: "MACSTR"\n", MAC2STR(node->lan_mac));
	vty_print_std("|	essid_id--------: "MACSTR"\n", MAC2STR(node->essid_id));
	vty_print_std("|	child_num-------: %d\n", node->child_num);
	vty_print_std("|	sta_num---------: %d\n", node->sta_num);
	vty_print_std("|	g_rates---------: %s\n", node->g_rates ? "supportG":"UNsupportG");
	vty_print_std("|	n_rates---------: %s\n", node->n_rates ? "supportN":"UNsupportN");
	vty_print_std("|	signal----------: %d\n", node->signal);
	vty_print_std("|	noise-----------: %d\n", node->noise);
//	vty_print_std("|	node_type-------: 0x%02X	[ bit7: bit6: bit5:wps bit4:INaplist(0)_INstalist(1) | bit3:wds bit2:ad-hoc bit1:sta bit0:ap ]\n", node->node_type);
	vty_print_std("|	node_type-------: %s%s%s%s%s%s\n",
								(node->node_type & 1<<0 ) ? "ap + ":"",
								(node->node_type & 1<<1 ) ? "sta + ":"",
								(node->node_type & 1<<2 ) ? "ad-hoc + ":"",
								(node->node_type & 1<<3 ) ? "wds + ":"",
								(node->node_type & 1<<5 ) ? "wps + ":"",
								(node->node_type & 1<<4 ) ? "INstalist":"INaplist"
								);
	vty_print_std("|	sta_num---------: %d\n", node->sta_num);
	vty_print_std("|	authed----------: %s\n", node->authed ? "yes":"no");
	vty_print_std("|	hide_ssid-------: %s\n", node->hide_ssid ? "yes":"no");
	vty_print_std("|	block_method----: %d\n", node->block_method);
	vty_print_std("+--------------------------------------\n");
}



int send_ap_info(struct w_node *node,char* func_name)
{

#if 1
//	static int i=0;
//open file and mmap
if( 0 == packet_syslog_out)
	return 0 ;

	  char *memory = NULL;
	  /*
	  int file_length = 0;
	  char *start_address = 0;
	  int fd = open( filename, O_RDONLY );
	  if ( fd > 0 )
	    {
	      file_length = lseek(fd, 1, SEEK_END);
	      memory = mmap( start_address, file_length, PROT_READ, MAP_SHARED, fd, 0 );
		
	    }else{
	    //vty_print_std("open file %s error\n",filename);
//	    	return -1;
	memory=NULL;
		}

*/

	
	//INIT_TABLE(WA_SOURCE_JF_1001);
	//	if(i%10==0)
//	vty_print_std("===========%s=================\n",func_name);
//	vsos_syslog_2(MODULE_ACD, 0,"===========%s================\n",func_name);
//	printf("file:%s,line:%d,func:%s:send ap info to server\n",__FILE__,__LINE__,__func__);
	//if(i%20==0)
//	dump_wnode_2_term(node);
//	dump_wnode_2_logserver(node);
	if(node->node_type & 1<<0)
	{
	
		send_WA_SOURCE_FJ_1001_to_logserver(node,memory);
	}else if(node->node_type & 1<<1 )
	{
		send_WA_SOURCE_FJ_1002_to_logserver(node,memory);
	}else{
			vsos_syslog_2(MODULE_ACD, 0,"unsuport 802.11 type from %s\n",func_name);
					send_WA_SOURCE_FJ_1002_to_logserver(node,memory);


}
/*
	close( fd );
      munmap( memory, file_length );

*/
	return 0;

#endif 

}
	#undef str_len
void update_wpolicy_list(int init)
{
	int ret,row=0,col=0;
	char query[512];
	char **dbResult;
	char *errmsg;
	struct list_tast *mp=NULL;

	if(!wpolicy_update_tag && !init)
		return;

	wpolicy_update_tag = 0;
	update_nodeinfo_list();
	get_object_ctime();
	
/*	update_subnet_hash();
	update_wgate_hash();*///for mem leak debug
			
	ret = sqlite3_open(WIPS_WCONFIG_DB,&sql_wconfig);
	if(ret != SQLITE_OK){
		WIPSD_DEBUG("[%s]open sqlite wconfig.db error !\n", __FUNCTION__);
		return;
	}

	//get wpolicy
	sprintf(query, "select * from wpolicy order by pid");
	ret = sqlite3_get_row( sql_wconfig, query, &dbResult, &row, &col, &errmsg);
	if(row > 0) {
		if(wpolicy_list != NULL) {
			XFREE(MTYPE_WIPS_DEBUG_WPOLICY_LIST,wpolicy_list);
			wpolicy_list = NULL;
		}

		wpolicy_num = row;
		wpolicy_list = XCALLOC(MTYPE_WIPS_DEBUG_WPOLICY_LIST,row*sizeof(struct wpolicy_struct));
		if(!wpolicy_list) {

	              if(sql_wconfig) {
	                  wipsd_sqlite3_close(sql_wconfig);
	                  sql_wconfig = NULL;
	              }

			WIPSD_DEBUG("no memory!");
			return;
		}

		wpolicy_index = 0;
		sprintf(query,"select * from wpolicy order by pid");
		sqlite3_exec(sql_wconfig, query, get_wpolicy, NULL,NULL);

		if(!init) {
			mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
			if(mp == NULL){
				WIPSD_DEBUG("malloc for new CMD_task err!\n");
				return;
			}

			memset(mp,0,sizeof(struct list_tast));

			mp->node = NULL;
			mp->task_type= LIST_TASK_UPDATE_WPOLICY;
			insertListTask(mp);
		}

	}
	else {
		wpolicy_num = 0;
		wpolicy_index = 0;
		if(wpolicy_list != NULL) {
			XFREE(MTYPE_WIPS_DEBUG_WPOLICY_LIST,wpolicy_list);
			wpolicy_list = NULL;
		}
	}

    if(sql_wconfig){
    	wipsd_sqlite3_close(sql_wconfig);
        sql_wconfig = NULL;
    }

	return;
}

#if NO_USE_CODE
void wipsd_update_timer_handler(struct ztimer *timer, void *arg)
{
	WIPSD_DEBUG("wipsd_update_timer_handler!\n");

	struct list_tast *mp=NULL;
	mp = malloc(sizeof(struct list_tast));
	if(mp == NULL){
		WIPSD_DEBUG("malloc for new list_task err!\n");
		return;
	}
	memset(mp,0,sizeof(struct list_tast));
	mp->task_type= LIST_TASK_CHECKWLIST;
	insertListTask(mp);

	ztimer_mod_sec(&wips_update_timer, 10);
	return;
}

int wipsd_init_timer(void)
{	
	WIPSD_DEBUG("wipsd_init_timer!\n");
	ztimer_init(&wips_update_timer, wipsd_update_timer_handler, NULL, master);
	ztimer_mod_sec(&wips_update_timer, 10);

	return 0;
}
#endif
static int thread_read_func(struct thread *thread)
{
	struct fdu *fdu = THREAD_ARG(thread);
	
	fdu->read_thread = NULL;
	fdu->read_handler(fdu, fdu->fd, fdu->read_arg);
	
	return 0;
}

void wipsd_handle_packet(struct fdu *fdu, int fd, void *arg)
{
	int bytes = 0;
//	int ret = 0;
//	int cfd = -1;
	int err = 0;
	u8 buf[WIPS_PKT_MAX_LEN];
	struct sockaddr_in addr;
	int addrLen = sizeof(struct sockaddr_in);
	struct wipsd_interface *wipsd_itf = NULL;
	
	if(!arg || !fdu){		
		WIPSD_DEBUG("Input param error!");
		return;
	}
	
	wipsd_itf = (struct wipsd_interface *)arg;
	memset((void *)buf, 0, sizeof(buf));
	
#if 1
	do {
		errno = 0;
		bytes = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrLen);
		if (bytes < 0){
			WIPSD_DEBUG("Recv packet failed(%d)!\t\n",bytes);
			goto OUT;
		}

		err = errno;
		if (err == EAGAIN || err == EINTR) {
			WIPSD_DEBUG("eagain or eintr happened!\t\n");
			continue;
		} else {
			break;
		}
	}while(err == EINTR);
#else 
	bytes = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrLen);
	if (bytes < 0){
		WIPSD_DEBUG("Recv packet failed(%d)!\t\n",bytes);
		goto OUT;
	}
#endif
	packet_counter++;
	packet_counter4show++;

	//WIPSD_DEBUG("Recv packet bytes(%d)!\t\n",bytes);
	//goto OUT;
	
	//WIPSD_DEBUG("packet counter %d!\t\n", packet_counter);
	wipsd_handle_wlansniffrm(buf, bytes, wipsd_itf, &addr);
	//WIPSD_DEBUG("wipsd_handle_wlansniffrm:%d\t\n",ret);
	task_stack();
#if 1
	time((time_t *)&fresh_time);
	while(fresh_time > (wireless_node_age + check_wlist_time)){
		struct list_tast *mp=NULL;
		mp = XMALLOC(MTYPE_WIPS_DEBUG_MP_NODE,sizeof(struct list_tast));
		if(mp == NULL){
			WIPSD_DEBUG("malloc for new list_task err!\n");
			break;
		}
		memset(mp,0,sizeof(struct list_tast));
		mp->task_type= LIST_TASK_CHECKWLIST;
		insertListTask(mp);
		check_wlist_time = fresh_time;
		break;
	}
#endif

	update_wpolicy_list(0);

#if 0
	if(fresh_time >= (10 + chek_keepalive_time)){
		chek_keepalive_time = fresh_time;
		update_wpolicy_list(0);
		update_wconfig_list();
	}
#endif
OUT:

#if 1
	fdu->read_handler = wipsd_handle_packet;
	fdu->read_arg = wipsd_itf;

	fdu->read_thread = 
		thread_add_read(master, thread_read_func, fdu, fdu->fd);

	if (fdu->read_thread == NULL){
		WIPSD_DEBUG("fdu->read_thread == NULL error\n");
		return ;
	}
#else
	if(!fdu_is_opened(fdu)){
		WIPSD_DEBUG("wipsd_handle_packet !fdu_is_opened() error\n");
		return;
	}
	ret = fdu_need_read(fdu, wipsd_handle_packet, wipsd_itf);
	if (ret < 0)
		WIPSD_DEBUG("wipsd_handle_packet fdu_need_read(): error:%d\n",ret);
#endif

	return;
}

extern int wipsd_wpolicy_edit_obj_data(u32 pid, u8 *mac, int type, enum nl_op_type cmd);
void wipsd_block_by_lan(int pid, struct w_node *node, int cmd)
{
	wipsd_wpolicy_edit_obj_data(pid, node->bssid, AP_MAC, cmd);
	
	wipsd_wpolicy_edit_obj_data(pid, node->mac, STA_MAC, cmd);
	return;
}

void wipsd_block_by_wireless(struct wipsd_ipc_data *data, struct w_node *node, int cmd)
{
	int ret = 0;
	struct wipsd_interface *wipsd_itf = NULL;

	if(!data || !node){
		WIPSD_DEBUG("[%s:%d]: debug!\n", __FUNCTION__, __LINE__);
		return;
	}

	if(!node->wipsd_itf){
		WIPSD_DEBUG("%s-%d, WIPSD_ITF is zero!\t\n", __FUNCTION__, __LINE__);
		return;
	}
	
	wipsd_itf = node->wipsd_itf;
	if(!node->addr.sin_addr.s_addr || !node->addr.sin_port){
		WIPSD_DEBUG("%s-%d, Send addr is zero!\t\n", __FUNCTION__, __LINE__);
		return;
	}

	data->cmd = cmd;

	WIPSD_DEBUG("Send to "NIPQUAD_FMT":%u.!\t\n", 
			NIPQUAD(node->addr.sin_addr.s_addr), ntohs(node->addr.sin_port));
#if 1		
	WIPSD_DEBUG("mac("MACSTR");bssid("MACSTR");channel(%d);band(%d);"
		"wgate_mac("MACSTR");block_method(%d);ipv4(%d);wgate_mac("MACSTR").\n", 
		MAC2STR(data->mac), MAC2STR(data->bssid), (int)data->channel, (int)data->freq_band,
		MAC2STR(data->wgate_mac), (int)data->block_method, data->ipv4, MAC2STR(data->wgate_mac));
#endif

	ret = sendto(wipsd_itf->rcv.fd, data, sizeof(*data), 0, (struct sockaddr *)&node->addr, sizeof(struct sockaddr_in));
	if(ret < 0){
		WIPSD_DEBUG("Send to "NIPQUAD_FMT":%u failed, err %d (%s)!\t\n", 
						NIPQUAD(node->addr.sin_addr.s_addr), ntohs(node->addr.sin_port), ret, strerror(errno));
		return;
	}
	
	return;
}

int wipsd_open_interface_sock(struct interface *itf, u32 ip, u16 port)
{
	int err = 0; 
	int sfd = 0;
	struct sockaddr_in addr;
	
	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sfd < 0) {
		WIPSD_DEBUG("Control socket create failed!\t\n");
		return E_SYSC_SOCKET;
	}

	err = sock_set_reuseaddr(sfd);
	if (err < 0){
		WIPSD_DEBUG("set reuseaddr failed!\t\n");
		goto EOUT_CLOSE;
	}

	memset((void *)&addr, 0, sizeof(struct sockaddr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);
	err = bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
	if (err < 0) {
		WIPSD_DEBUG("Bing socket to addr "NIPQUAD_FMT":%u failed, err %d!\t\n", 
							NIPQUAD(addr.sin_addr.s_addr), port, err);
		close(sfd);
		return E_SYSC_BIND;
	}

	err = fd_set_nonblocking(sfd);
	if (err < 0){
		WIPSD_DEBUG("set nonblocking failed!\t\n");
		goto EOUT_CLOSE;
	}

#if 0	
	err = sock_bind_device(sfd, itf->name);
	if (err < 0){
		WIPSD_DEBUG("bind device %s failed!\t\n", itf->name);
		goto EOUT_CLOSE;
	}
#endif

	return sfd;
EOUT_CLOSE:
	close(sfd);
	return err;
}


int wipsd_init_socket(struct wipsd_interface *wipsd_if)
{
//	int err = 0;
	int cfd = 0;
	struct fdu *rcv = &wipsd_if->rcv;

	if(!wipsd_if || !wipsd_if->itf || !rcv ||!wipsd_if->ip){
		WIPSD_DEBUG("wipsd_init_socket have null param!\t\n");
		return 1;
	}
	
	if (fdu_is_opened(rcv)){
		WIPSD_DEBUG("rcv socket is opened!\t\n");
		goto OUT;
	}
	
	cfd = wipsd_open_interface_sock(wipsd_if->itf, wipsd_if->ip, WIPSD_SOCKET_PORT);
	if (cfd < 0)
		return cfd;
	
	fdu_open(rcv, cfd);

#if 1	
	rcv->read_handler = wipsd_handle_packet;
	rcv->read_arg = wipsd_if;
	rcv->read_thread = 
		thread_add_read(master, thread_read_func, rcv, rcv->fd);
#else
	err = fdu_need_read(rcv, wipsd_handle_packet, wipsd_if);
	if (err < 0){
		WIPSD_DEBUG("fdu_need_read() error:%d\n",err);
	}
#endif

OUT:
	return 0;
}

static inline struct interface *wipsd_if_get(const struct wipsd_interface *wipsd_if)
{
	if (wipsd_if == NULL){
		return NULL;
	}
	
	return wipsd_if->itf;
}

static int wipsd_if_can_start(struct interface *itf)
{
	if (!if_is_up(itf)) {
		WIPSD_DEBUG("Interface %s is down, wipsd interfacecan not run!\t\n", 
		            itf->name);
		return 1;
	}
	
	if (if_get_ip_count(itf) == 0) {
		WIPSD_DEBUG("Wipsd interface %s can't start without ip address!\t\n", itf->name);
		return 1;
	}
	
	return 0;
}

struct wipsd_interface *wipsd_if_create(struct interface *itf)
{
	struct wipsd_interface *wipsd_if = NULL;	
	
	wipsd_if = XMALLOC(MTYPE_WIPSD_INTERFACE, sizeof(struct wipsd_interface));
	if(!wipsd_if){
		WIPSD_DEBUG("Malloc memory for wipsd_if failed!\t\n");
		return NULL;
	}
	
	memset((void *)wipsd_if, 0, sizeof(struct wipsd_interface));
	INIT_LIST_HEAD(&wipsd_if->list);
	wipsd_if->itf = itf;
	fdu_init(&wipsd_if->rcv, master);
	itf->info = (void *)wipsd_if;

	return wipsd_if;
}

int wipsd_if_start(struct wipsd_interface *wipsd_if)
{
	int ret = 0;
	struct interface *itf = wipsd_if_get(wipsd_if);

	if( !itf){
		WIPSD_DEBUG("wipsd if start input param error!\t\n");
		return 1;
	}

	ret = wipsd_if_can_start(itf);
	if(ret){
		WIPSD_DEBUG("wipsd can't start now!\t\n");
		return 1;
	}
	
	wipsd_if->ip = if_get_primary_ip(itf);
	ret = wipsd_init_socket(wipsd_if);
	if(ret){
		WIPSD_DEBUG("init socket failed!\t\n");
		//XFREE(MTYPE_WIPSD_INTERFACE, wipsd_if);
		return 1;
	}

	return 0;
}

int wipsd_if_stop(struct wipsd_interface *wipsd_if)
{
//	int fd = 0;
//	struct thread *thread = NULL;
	
	if(!wipsd_if){
		WIPSD_DEBUG("%s-%d: wipsd_if is null!\t\n", __FUNCTION__, __LINE__);
		return 0;
	}

	if(wipsd_if->rcv.fd < 0 || !wipsd_if->rcv.master){
		WIPSD_DEBUG("%s-%d: wipsd_if fd is unavailable!\t\n", __FUNCTION__, __LINE__);
		return 0;
	}

#if 1
	if (wipsd_if->rcv.read_thread){
		thread_cancel(wipsd_if->rcv.read_thread);
	}
	close(wipsd_if->rcv.fd);
	wipsd_if->rcv.fd = -1;
#else
	fd = fdu_close(&(wipsd_if->rcv));
	if(fd >= 0){
		WIPSD_DEBUG("%s-%d: wipsd_if fd fdu_close(fd:%d)!\t\n", __FUNCTION__, __LINE__,fd);
		close(fd);
		fd = -1;

	}
#endif
	
	return 0;
}

int wipsd_if_destroy(struct wipsd_interface *wipsd_if)
{

	if(!wipsd_if){
		WIPSD_DEBUG("wipsd_if_destroy: wipsd_if is null!\t\n");
		return 1;
	}
	
	wipsd_if_stop(wipsd_if);

	return 0;
}

static int wipsd_if_new_hook(struct interface *itf)
{
	return 0;
}

static int wipsd_if_free_hook(struct interface *itf)
{
	return 0;
}

static int wipsd_if_add(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *itf = NULL;

	itf = zebra_interface_add_read(zclient->ibuf);
	if (!itf) {
		WIPSD_DEBUG("zebra_interface_add_read()\n");
		return 0;
	}

	return 0;
}

static int wipsd_if_delete(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	itf = zebra_interface_state_read(zclient->ibuf);
	if (!itf) {
		WIPSD_DEBUG("zebra_interface_state_read()\n");
		return 0;
	}

	wipsd_if = itf->info;
	if(!wipsd_if)
		goto OUT;
	
	wipsd_if_destroy(wipsd_if);
	itf->info = NULL;
	list_del(&wipsd_if->list);
	XFREE(MTYPE_WIPSD_INTERFACE, wipsd_if);
	wipsd_itf_list->cnt--;
	
OUT:
	if_delete(itf);

	return 0;
}

static int wipsd_if_up(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	itf = zebra_interface_state_read(zclient->ibuf);
	if (!itf) {
		WIPSD_DEBUG("zebra_interface_state_read()!\t\n");
		return 0;
	}

	if(!strncmp(itf->name, "eth", 3) || 
		!strncmp(itf->name, "lo", 2)){
		return 0;
	}

	wipsd_if = itf->info;
	if(!wipsd_if || !wipsd_if->itf){
		WIPSD_DEBUG("zebra_interface_state_read()-%d!\t\n", __LINE__);
		return 0;
	}
		
	wipsd_if_start(wipsd_if);
	
	return 0;
}

static int wipsd_if_down(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;

	itf = zebra_interface_state_read(zclient->ibuf);
	if (!itf) {
		WIPSD_DEBUG("zebra_interface_state_read()\n");
		return 0;
	}

	if(!strncmp(itf->name, "eth", 3) || 
		!strncmp(itf->name, "lo", 2)){
		return 0;
	}

	wipsd_if = itf->info;
	if(!wipsd_if)
		return 0;
	
	wipsd_if_stop(wipsd_if);
	
	return 0;
}

static int wipsd_if_address_add(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;
	struct connected *ifc = NULL;
	struct prefix *addr = NULL;

	ifc = zebra_interface_address_add_read(zclient->ibuf);
	if (!ifc || !(itf = ifc->ifp) || !(addr = ifc->address)) {
		WIPSD_DEBUG("zebra_interface_address_add_read()\n");
		return 0;
	}
	
	if(!strncmp(itf->name, "eth", 3) || 
		!strncmp(itf->name, "lo", 2)){
		return 0;
	}

	wipsd_if = itf->info;
	if(!wipsd_if)
		return 0;
	
	wipsd_if_start(wipsd_if);
	
	return 0;
}

static int wipsd_if_address_delete(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *itf = NULL;
	struct wipsd_interface *wipsd_if = NULL;
	struct connected *ifc = NULL;
	struct prefix *addr = NULL;

	ifc = zebra_interface_address_delete_read(zclient->ibuf);
	if (!ifc || !(itf = ifc->ifp) || !(addr = ifc->address)) {
		WIPSD_DEBUG("zebra_interface_address_delete_read()\n");
		goto OUT;
	}

	if(!strncmp(itf->name, "eth", 3) || 
		!strncmp(itf->name, "lo", 2)){
		return 0;
	}

	if (addr->family != AF_INET)
		goto OUT;
	
	wipsd_if = itf->info;
	if(!wipsd_if)
		return 0;

	if(if_get_ip_count(itf) == 0)
		wipsd_if_stop(wipsd_if);

OUT:
	if (ifc)
		connected_free(ifc);
	
	return 0;
}

void wipsd_if_register(void)
{
	if_add_hook(IF_NEW_HOOK, wipsd_if_new_hook);
	if_add_hook(IF_DELETE_HOOK, wipsd_if_free_hook);
	
	zclient->interface_add = wipsd_if_add;
 	zclient->interface_delete = wipsd_if_delete;
  	zclient->interface_up = wipsd_if_up;
  	zclient->interface_down = wipsd_if_down;
  	zclient->interface_address_add = wipsd_if_address_add;
  	zclient->interface_address_delete = wipsd_if_address_delete;
}
