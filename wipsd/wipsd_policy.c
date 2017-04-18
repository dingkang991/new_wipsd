#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include "zthread_support.h"
#include "wipsd_wnode.h"
#include "wipsd.h"
#include "wipsd_policy.h"

wpolicy_struct		*wpolicy_list = NULL;
wevent_struct		*wevent_list = NULL;
int wpolicy_index = 0;
int wpolicy_num = 0;

extern wevent_struct	*wevent_list;
extern sqlite3 *sql_wconfig;

#if 0
extern wpolicy_struct	*wpolicy_list;
extern wevent_struct	*wevent_list;
extern int wpolicy_index;
extern int wpolicy_num;
#endif

int get_by_apname(void* data, int n_columns, char** column_values, char** column_names)
{
	if(column_values[4])
		strncpy(wpolicy_list[wpolicy_index].ap_mac, column_values[4], 17);
	
	if(column_values[5])
		strncpy(wpolicy_list[wpolicy_index].vendor, column_values[5], 127);

	return 0;
}

int get_by_staname(void* data, int n_columns, char** column_values, char** column_names)
{
	if(column_values[1])
		strncpy(wpolicy_list[wpolicy_index].sta_mac, column_values[1], 17);

	if( column_values[2])
		strncpy(wpolicy_list[wpolicy_index].sta_mac_mask, column_values[2], 3);

	if( column_values[3])
		strncpy(wpolicy_list[wpolicy_index].vendor, column_values[3], 127);

	return 0;
}

int get_wpolicy(void* data, int n_columns, char** column_values, char** column_names)
{
	char query[512];
	int i;

	if(wpolicy_index >= wpolicy_num || !column_values[2] || !column_values[3] || !column_values[4]
		|| !column_values[5] || !column_values[6] || !column_values[7] || !column_values[8])
		return 0;

	wpolicy_list[wpolicy_index].wpid = atoi(column_values[1]);

	strncpy(wpolicy_list[wpolicy_index].wnet, column_values[2], SSID_BUFSIZE-1);
	strncpy(wpolicy_list[wpolicy_index].ap_name, column_values[3], 63);
	strncpy(wpolicy_list[wpolicy_index].sta_name, column_values[4], 63);
	strncpy(wpolicy_list[wpolicy_index].wevent, column_values[5], WEVENT_NAME_LEN_L);
	strncpy(wpolicy_list[wpolicy_index].ctime, column_values[6], 31);
	strncpy(wpolicy_list[wpolicy_index].waction, column_values[7], 7);
	strncpy(wpolicy_list[wpolicy_index].enable, column_values[8], 7);
	if(column_values[9])
		wpolicy_list[wpolicy_index].channel= atoi(column_values[9]);

	if(strncmp(wpolicy_list[wpolicy_index].ap_name, "any", 3) != 0) {
		sprintf(query,"select * from aplist where name=\"%s\"", wpolicy_list[wpolicy_index].ap_name);
		sqlite3_exec(sql_wconfig, query, get_by_apname, NULL,NULL);
	}

	if(strncmp(wpolicy_list[wpolicy_index].sta_name, "any", 3) != 0) {
		sprintf(query,"select * from stalist where name=\"%s\"", wpolicy_list[wpolicy_index].sta_name);
		sqlite3_exec(sql_wconfig, query, get_by_staname, NULL,NULL);
	}

	for(i=WIPS_EID_MIN; i< WIPS_EID_MAX; i++) {
		if(strcmp(wpolicy_list[wpolicy_index].wevent, wevent_list[i-1].cmd_name) == 0) {
			wpolicy_list[wpolicy_index].weid = i;
			break;
		}
	}

#ifdef DEBUG_WIPSD		
	WIPSD_DEBUG("%s-%d:wpolicy(%d):weid:%d; wnet:%s; ap_name:%s; sta_name:%s; wevent:%s; ctime:%s; waction:%s; enable:%s; channel:%d; ap_mac:%s; sta_mac:%s.\n", 
	    __func__, __LINE__,
	    wpolicy_list[wpolicy_index].wpid,wpolicy_list[wpolicy_index].weid,wpolicy_list[wpolicy_index].wnet,
		wpolicy_list[wpolicy_index].ap_name,wpolicy_list[wpolicy_index].sta_name,wpolicy_list[wpolicy_index].wevent,
		wpolicy_list[wpolicy_index].ctime,wpolicy_list[wpolicy_index].waction,wpolicy_list[wpolicy_index].enable,
		wpolicy_list[wpolicy_index].channel,wpolicy_list[wpolicy_index].ap_mac, 
		wpolicy_list[wpolicy_index].sta_mac);
#endif

	wpolicy_index++;
	return 0;
}

