#ifndef __WDISP_H__
#define __WDISP_H__

#include <linux/types.h>
#define AP_PIX_X 32
#define AP_PIX_Y 32
#define STA_PIX_X 16
#define STA_PIX_Y 16

typedef struct sta_node
{
	char ssid[32];
	char mac[24];
	char bssid[24];
	char rates[8];
	char signal[8];
	char noise[8];
	char channel[8];
	char ipaddr[16];
	char vendor[128];
	char osf[32];
	char osg[32];
	char alert[32];
	char up_time[32];
	char last_time[32];
	char name[32];
	char type[32];
	__u32 id;
	__u32 block;

	struct ap_node *pap;
	struct sta_node *psta;
}sta_node;

typedef struct ap_node
{
	char ssid[32];
	char mac[24];
	char interval[8];
	char g_rates[8];
	char n_rates[8];
	char signal[8];
	char noise[8];
	char channel[8];
	char sec_type[40];
	char ipaddr[16];
	char vendor[128];
	char osf[32];
	char osg[32];
	char alert[32];
	char up_time[32];
	char last_time[32];
	char name[32];
	char type[32];
	__u32 id;
	__u32 block;

	__u32 sta_num;
	struct sta_node *psta;
}ap_node;

typedef struct vendor_node
{
	char mac[24];
	char vendor[128];

}vendor_node;

#define MAX_DISP_AP 100
#define MAX_DISP_STA 200
#define SQL_GET_ALL_AP "select * from beacon_test1 order by last_time desc limit 100"
#define SQL_GET_ALL_STA "select * from sta_list order by last_time desc limit 200"

#define SQL_GET_ALL_INTER_AP "select * from beacon_test1 where ipaddr!=\"0\" and ipaddr!=\"\""
#define SQL_GET_ALL_EXTER_AP "select * from beacon_test1 where (ipaddr=\"0\" or ipaddr is null)"
#define SQL_GET_ALL_INTER_STA "select * from sta_list where ipaddr!=\"0\" and ipaddr!=\"\""
#define SQL_GET_ALL_EXTER_STA "select * from sta_list where (ipaddr=\"0\" or ipaddr is null)"

#define SQL_GET_ALL_ACTIVE_AP "select * from beacon_test1 where last_time>datetime('now','localtime','-5 minute') or up_time>datetime('now','localtime','-5 minute')"
#define SQL_GET_ALL_ACTIVE_STA "select * from sta_list where last_time>datetime('now','localtime','-5 minute') or up_time>datetime('now','localtime','-5 minute')"
#define SQL_GET_ACTIVE_INTER_AP "select * from beacon_test1 where ipaddr!=\"0\" and ipaddr!=\"\" and (last_time>datetime('now','localtime','-5 minute') or up_time>datetime('now','localtime','-5 minute'))"
#define SQL_GET_ACTIVE_EXTER_AP "select * from beacon_test1 where (ipaddr=\"0\" or ipaddr is null) and (last_time>datetime('now','localtime','-5 minute') or up_time>datetime('now','localtime','-5 minute'))"
#define SQL_GET_ACTIVE_INTER_STA "select * from sta_list where ipaddr!=\"0\" and ipaddr!=\"\" and (last_time>datetime('now','localtime','-5 minute') or up_time>datetime('now','localtime','-5 minute'))"
#define SQL_GET_ACTIVE_EXTER_STA "select * from sta_list where (ipaddr=\"0\" or ipaddr is null) and (last_time>datetime('now','localtime','-5 minute') or up_time>datetime('now','localtime','-5 minute'))"


#define SQL_GET_ALL_NO_VENDOR_AP "select * from beacon_test1 where vendor=\"\" or vendor is null"
#define SQL_GET_ALL_NO_VENDOR_STA "select * from sta_list where vendor=\"\" or vendor is null"

#define SQL_GET_ALL_ALONE_STA "select * from sta_list where bssid not in (select mac from beacon_test1)"
#endif
