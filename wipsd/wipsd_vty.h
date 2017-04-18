#ifndef __WIPSD_VTY_H__
#define __WIPSD_VTY_H__


#ifndef OBJ_DATA_MAX_LEN
#define OBJ_DATA_MAX_LEN		128
#endif

#ifndef OBJ_PID_MAX
#define OBJ_PID_MAX		100
#endif

#ifndef OBJ_NAME_MAX_LEN
#define OBJ_NAME_MAX_LEN		64
#endif

#ifndef OBJ_SHORT_NAME_MAX_LEN
#define OBJ_SHORT_NAME_MAX_LEN		32
#endif

#ifndef OBJ_IP_MAX_LEN
#define OBJ_IP_MAX_LEN		24
#endif

#ifndef OBJ_TIME_MAX_LEN
#define OBJ_TIME_MAX_LEN		20
#endif

#ifndef OBJ_TYPE_MAX_LEN
#define OBJ_TYPE_MAX_LEN		16
#endif

#ifndef XML_MAX_ALARM_LEVEL_LEN
#define XML_MAX_ALARM_LEVEL_LEN	8
#endif

#ifndef XML_MAX_CHANNEL_LEN
#define XML_MAX_CHANNEL_LEN	4
#endif

#ifndef XML_MAX_PERMIT_LEN
#define XML_MAX_PERMIT_LEN	4
#endif

#define WIPSD_CONFIG_FILE_PATH "/usr/local/etc/wipsd.conf"
#define CONFIG_FILE_TMP_PATH "/usr/hls/etc/.config.tmp"

#define CONFIG_LIC_FILE_PATH "/usr/hls/etc/license.enc"
#define CONFIG_AUTO_SAVE_TIME 15 /* seconds */

#define WIPSD_CONFIG_DEBUG_ON		1
#define WIPSD_CONFIG_DEBUG_OFF		0

#define WIPSD_EVENT_MAX 1000
#define WIPSD_SUSPENDING_PACKAGE_NUM 10000
enum {
 	WIPSD_LOG_TYPE_ALL = 0,
 	WIPSD_LOG_TYPE_LOCAL,
 	WIPSD_LOG_TYPE_REMOTE,
};

#define WIPSD_LOG_TYPE(type) \
	(type == WIPSD_LOG_TYPE_ALL)?"all": \
	(type == WIPSD_LOG_TYPE_LOCAL)?"local": \
	(type == WIPSD_LOG_TYPE_REMOTE)?"remote": ""


enum wipsd_ipc_err
{
	WIPSD_OK = 0,

	WIPSD_ERR_SQL_PROCESS,
	WIPSD_ERR_TRANS_FAULT,
	WIPSD_ERR_MALLOC,
	WIPSD_ERR_UNKNOW_CMD,
	WIPSD_ERR_UNKOWN,
	
	WIPSD_ERR_WNET_EXIST,
	WIPSD_ERR_WNET_UNEXIST,
	WIPSD_ERR_WNET_UNAVAILABLE,
	WIPSD_ERR_WNET_USED,

	WIPSD_ERR_AP_EXIST,
	WIPSD_ERR_AP_RADIO_MAC_EXIST,
	WIPSD_ERR_AP_UNEXIST,
	WIPSD_ERR_AP_UNAVAILABLE,
	WIPSD_ERR_AP_USED,

	WIPSD_ERR_STA_EXIST,
	WIPSD_ERR_STA_MAC_EXIST,
	WIPSD_ERR_STA_UNEXIST,
	WIPSD_ERR_STA_UNAVAILABLE,
	WIPSD_ERR_STA_USED,

	WIPSD_ERR_WPO_EXIST,
	WIPSD_ERR_WPO_UNEXIST,
	WIPSD_ERR_WPO_UNAVAILABLE,

	WIPSD_ERR_SQL_WRITE,
	WIPSD_ERR_ADD_FAIL,
	WIPSD_ERR_DEL_FAIL,
	WIPSD_ERR_CONFIG_FAIL,
	WIPSD_ERR_OPEN_FILE,
	WIPSD_ERR_CODE_MAX,
	WIPSD_ERR_WRONG_IP,

	WIPSD_ERR_INTERFACE_EXIST,
	WIPSD_ERR_INTERFACE_UNEXIST,
	WIPSD_ERR_INTERFACE_UNAVAILABLE,
	
	WIPSD_ERR_MAX
};

enum wipsd_ipc_cmd
{
	WIPSD_IPC_OK = 0,

	WIPSD_WNET_CONFIG,
	WIPSD_WNET_ADD,
	WIPSD_WNET_DEL,
	WIPSD_WNET_MOD,
	WIPSD_WNET_LEARN,
	WIPSD_WNET_DUMP,
	WIPSD_WNET_AP,
	WIPSD_WNET_MONITOR,
	WIPSD_WNET_ENCRYPT_CONFIG,
	WIPSD_WNET_MODE_CONFIG,
	WIPSD_WNET_GATEWAY_CONFIG,
	WIPSD_WNET_MAC_CONFIG,
	WIPSD_WNET_TIME_RANGE_CONFIG,

	WIPSD_AP_CONFIG,
	WIPSD_AP_ADD,
	WIPSD_AP_DEL,
	WIPSD_AP_MOD,
	WIPSD_AP_LEARN,
	WIPSD_AP_DUMP,
	WIPSD_AP_LEARN_DUMP,
	WIPSD_AP_COMPANY_CONFIG,

	WIPSD_STA_CONFIG,
	WIPSD_STA_ADD,
	WIPSD_STA_DEL,
	WIPSD_STA_MOD,
	WIPSD_STA_LEARN,
	WIPSD_STA_DUMP,
	WIPSD_STA_LEARN_DUMP,
	WIPSD_STA_COMPANY_CONFIG,

	WIPSD_SUBNET_CONFIG,
	WIPSD_SUBNET_ADD,
	WIPSD_SUBNET_DEL,
	WIPSD_SUBNET_MOD,
	WIPSD_SUBNET_DUMP,

	WIPSD_VENDOR_CONFIG,
	WIPSD_VENDOR_ADD,
	WIPSD_VENDOR_DEL,
	WIPSD_VENDOR_MOD,
	WIPSD_VENDOR_LEARN,
	WIPSD_VENDOR_DUMP,
		
	WIPSD_POLICY_CONFIG,
	WIPSD_POLICY_ADD,
	WIPSD_POLICY_DEL,
	WIPSD_POLICY_MOD,
	WIPSD_POLICY_MOVE,
	WIPSD_POLICY_LEARN,
	WIPSD_POLICY_DUMP,
	WIPSD_POLICY_ENABLE,

	WIPSD_WIPS_EVENT_DUMP,

	WIPSD_CONFIG_DUMP,
	
	WIPSD_CONFIG_INTERFACE,
	WIPSD_CONFIG_INTERFACE_ADD,
	WIPSD_CONFIG_INTERFACE_DEL,
	WIPSD_CONFIG_INTERFACE_CHECK_EXIST,

	WIPSD_CONFIG_DEBUG,
	WIPSD_CONFIG_SET_DEBUG,
	WIPSD_CONFIG_SHOW_DEBUG,

	WIPSD_CONFIG_LOG,
	WIPSD_CONFIG_LOG_SET,
	WIPSD_CONFIG_IP_PORT_SET,
	WIPSD_SET_SIGNAL_THRESHOLD_LOG,
	WIPSD_SET_WIRELESS_DEAD_TIME,
	WIPSD_SET_WIRELESS_AGE,
	WIPSD_SET_SHOW_ALL_INFO,
	WIPSD_SET_PACKET_SYSLOG_OUT,
	WIPSD_SET_EVENT_SYSLOG_OUT,


	WIPSD_IPC_MAX,
};

struct wipsd_wnet_trans
{
	u8 name[OBJ_NAME_MAX_LEN];
	u8 type[OBJ_TYPE_MAX_LEN];
	u8 auth[OBJ_SHORT_NAME_MAX_LEN];
	u8 mode[OBJ_SHORT_NAME_MAX_LEN];
	u8 start_time[OBJ_TIME_MAX_LEN];
	u8 end_time[OBJ_TIME_MAX_LEN];
	u8 gw[OBJ_IP_MAX_LEN];
	u8 mac[ETH_ALEN];
};

struct wipsd_wnet_st
{
	u32 cmd;
	struct wipsd_wnet_trans trans;
};

struct wipsd_ap_trans
{
	
	u8 name[OBJ_SHORT_NAME_MAX_LEN];
	u8 type[OBJ_TYPE_MAX_LEN];
	u8 ip[OBJ_IP_MAX_LEN];
	u8 mmac[ETH_ALEN];
	u8 wmac[ETH_ALEN];
	u8 vendor[OBJ_DATA_MAX_LEN];
};

struct wipsd_ap_st
{
	u32 cmd;
	struct wipsd_ap_trans trans;
};

struct wipsd_ap_info_trans
{
	u8 name[OBJ_SHORT_NAME_MAX_LEN];
	u8 mode[OBJ_SHORT_NAME_MAX_LEN];
	u8 sec_type[OBJ_NAME_MAX_LEN];
	u8 ssid[OBJ_NAME_MAX_LEN];
	u8 type[OBJ_TYPE_MAX_LEN];
	u8 ip[OBJ_IP_MAX_LEN];
	u8 mmac[ETH_ALEN];
	u8 wmac[ETH_ALEN];
	u8 pmac[ETH_ALEN];
	u8 band;
	u8 channel;
	u8 internal;
	u8 vendor[OBJ_DATA_MAX_LEN];
	u32 signal;
	u32 noise;
	time_t up_time;
	time_t last_time;
};

struct wipsd_ap_info_st
{
	u32 cmd;
	struct wipsd_ap_info_trans trans;
};

struct wipsd_sta_trans
{
	u8 name[OBJ_SHORT_NAME_MAX_LEN];
	u8 mac[ETH_ALEN];
	u32 mask;
	u8 vendor[OBJ_DATA_MAX_LEN];
};

#define SEARCH_BY_BSSID 0x1
#define SEARCH_BY_MAC 0x2
#define SEARCH_BY_PROBER 0x4
struct wipsd_sta_ap_show
{
	u8 show_all_info;
	u8 search_opt;
	u8 mac[ETH_ALEN];
};


struct wipsd_sta_st
{
	u32 cmd;
	struct wipsd_sta_trans trans;
};

struct wipsd_sta_info_trans
{
	u8 name[OBJ_SHORT_NAME_MAX_LEN];
	u8 mac[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	u8 pmac[ETH_ALEN];
	u8 mode[OBJ_SHORT_NAME_MAX_LEN];
	u8 sec_type[OBJ_NAME_MAX_LEN];
	u8 band;
	u8 channel;
	u8 vendor[OBJ_DATA_MAX_LEN];
	u8 placeholder;
    u8 is_assoc2ap;
	u32 signal;
	u32 noise;
	u32 mask;
	time_t up_time;
	time_t last_time;
};

struct wipsd_sta_info_st
{
	u32 cmd;
	struct wipsd_sta_info_trans trans;
};

struct wipsd_subnet_trans
{
	u8 name[OBJ_NAME_MAX_LEN];
	u8 mac[ETH_ALEN];
};

struct wipsd_subnet_st
{
	u32 cmd;
	struct wipsd_subnet_trans trans;
};

struct wipsd_vendor_trans
{
	u8 name[OBJ_NAME_MAX_LEN];
	u8 type[OBJ_NAME_MAX_LEN];
	u8 mac[ETH_ALEN];
	u32 mask;
	u8 key[OBJ_NAME_MAX_LEN];
};

struct wipsd_vendor_st
{
	u32 cmd;
	struct wipsd_vendor_trans trans;
};

struct wipsd_policy_trans
{
	u32 pid;
	u8 wnet[OBJ_NAME_MAX_LEN];
	u8 ap[OBJ_SHORT_NAME_MAX_LEN];
	u8 sta[OBJ_SHORT_NAME_MAX_LEN];
	//u8 weventid;
	u8 wevent[OBJ_NAME_MAX_LEN];
	u8 waction[8];
	u8 enable[8];
	u32 channel;
};

struct wipsd_wips_event_st
{
	u32 start;
	u32 num;
};

struct wipsd_wips_event_trans
{
	u32 log_num;
	u8 bssid[24];
	u8 mac[24];
	u8 channel[4];
	u8 alert[128];
	u8 permit[4];
	u8 pri[8];
	u8 up_time[24];
	u8 name[OBJ_NAME_MAX_LEN];
	u8 ssid[OBJ_NAME_MAX_LEN];

};
struct wipsd_policy_st
{
	u32 cmd;
	struct wipsd_policy_trans trans;
};

struct wipsd_policy_sap_trans
{
	u8 ds;
	u8 ap_mac[ETH_ALEN];
	u8 sta_mac[ETH_ALEN];
};

enum{
	WIPSD_CONFIG_INFO,
	WIPSD_CONFIG_SYS_LOG,
	WIPSD_INTERFACE_LIST_INFO,
	WIPSD_CONFIG_WIPS_SYSLOG_OUT,
};

struct wipsd_info_trans{
	int info;
};

struct wipsd_log_trans{
	int log_type;
	u32 syslog_ip;
	u16 syslog_port;
};

struct wipsd_log_trans_st{
	u32 cmd;
	struct wipsd_log_trans trans;
};

struct wipsd_interface_trans
{
	u8 enable;
	u8 name[IFNAMSIZ];
};

struct wipsd_config_trans{
	u8 type;
	union {
		struct wipsd_info_trans info;
		struct wipsd_log_trans log;
		struct wipsd_interface_trans interface;
	}data;
};

struct wipsd_interface_st
{
	u32 cmd;
	struct wipsd_interface_trans trans;
};

struct wipsd_debug_trans
{
	u8 debug;
};

struct wipsd_debug_st
{
	u32 cmd;
	struct wipsd_debug_trans trans;
};


#endif

