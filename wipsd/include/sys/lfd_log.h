#ifndef __LFD_LOG_H__
#define __LFD_LOG_H__

#define HAVE_SYSLOG_H
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <assert.h>

#define DELIM  "="

//static char log_server_ip[32];


#ifndef HAVE_SYSLOG_H
#define LOG_ALERT			1
#define LOG_CRIT				2
#define LOG_ERR				3
#define LOG_WARNING		4
#define LOG_NOTICE			5
#define LOG_INFO			6
#define LOG_DEBUG			7
#define LOG_EMERG			0
#endif

#define MAX_KEY_WORD_LEN 32
#define MAX_PRE_STRING MAX_KEY_WORD_LEN + sizeof("=")
#define P(x) ((x != NULL)?(x):"")
//static char hostname[128] = {'\0'};

enum daemon_type{
	EVENT,
	SYSTEM
};

enum facility{
	WEVENT = 67,
	WSYSTEM	
};

typedef struct daemon{
	char 	*name;
	char 	*keyword;
	enum facility fac;  
}DAEMON;



enum kw_type{
	DIGITAL = 0,
	STRING	
};

enum log_type{
	LOG_ALL = 0,
	LOG_EVENT,
	LOG_SYSTEM	
};

struct key_word{
	const char 		* name;
	enum kw_type 	kw_type;
	__u32			maxsize;
	enum log_type	grp;
	char  			*meaning;	
};

enum keyword_id{
	WIPS_SERIALNUM = 0,
	WIPS_GENTIME,	
	WIPS_EVECOUNT,
	WIPS_EVEID,
	WIPS_EVECONTENT,
	WIPS_IP ,
	WIPS_MAC,	
	WE_BSSID,
	WE_SSID,
	WE_MAC,
	WE_WMAC,
	WE_PROTOCOL,
	WE_DEV_TYPE,
	WE_SECURITY,
	WE_CHANNEL,
	WE_SIGNAL,
	WE_NOISE,
	WE_RATES,
	WE_IPADDR,
	WE_VENDOR,
	WE_UP_TIME,
	WE_LAST_TIME,
	WE_GRP_NAME,
	WE_EVENT_NAME,
	WE_BLK_FLG,
	WE_PRI,
	WE_OBJ_NAME,

	WS_TIME,
	WS_TYPE,
	WS_SOURCE,
	WS_USER,
	WS_INFO	
};


#include "wipsd_wnode.h"
#if 0
enum {
	WIPS_EID_ALL = WIPS_EID_MIN,//1

	WIPS_EID_ERR_CFG_GRP,//2
	WIPS_EID_NO_CRYPT_AP,
	WIPS_EID_CRYPT_WEP_AP,
	WIPS_EID_WPS_AP,
	WIPS_EID_WDS_AP,
	WIPS_EID_WDS_STA,
	WIPS_EID_AD_HOC,
	WIPS_EID_AD_PKG,
	WIPS_EID_UNAUTH_AP,
//	WIPS_EID_INVALID_FREQ_AP,
	WIPS_EID_STA_PROXY_AP,
	WIPS_EID_CLOSE_PSPE,
//	WIPS_EID_UNAUTH_MAC_FACT,
	WIPS_EID_WPA_REFUSED,
	WIPS_EID_FORBID_CHANNEL,
	WIPS_EID_UNAUTH_ESSID,
	WIPS_EID_AP_BRAODCAST_SSID,
	WIPS_EID_AP_DEFAULTSSID,
	WIPS_EID_UNAUTH_STA,
	WIPS_EID_AUTHSTA_UNAUTHAP,
//	WIPS_EID_UNAUTH_DHCP,
	WIPS_EID_AUTHSTA_EXTAP,
	WIPS_EID_UNAUTHSTA_INTERAP,
//	WIPS_EID_AP_FORBIDRATE,
//	WIPS_EID_STA_FORBIDRATE,

	WIPS_EID_PROBE_GRP,//22
//	WIPS_EID_NULLPROBE_RESP,
	WIPS_EID_UNAUTHSTA_PROBE_TOOMANY,

	WIPS_EID_SPOOFING_GRP,//24
	WIPS_EID_FISHING_AP,/* == WIPS_EID_FAKESSID_AP, */
	WIPS_EID_HOTSPOTTER_AP,
	WIPS_EID_AIRBASE_NG_FAKE_AP,
	WIPS_EID_MDK3_BEACON_FLOOD_AP,
	WIPS_EID_MITM_ATTACK,
	WIPS_EID_ARP_SPOOFING_ATTACK,
	WIPS_EID_SEND2_ITSELF,
	WIPS_EID_AP_SIGNAL_TOOHIGH,
	WIPS_EID_TOOMANY_AP_INACHANNEL,
	WIPS_EID_ADHOC_SSID_AP_SSID_SAME,
//	WIPS_EID_STA_FAKE_AS_AP,
	WIPS_EID_STA_SIGNAL_TOOHIGH,

	WIPS_EID_DOS_GRP,//36
	WIPS_EID_DEAUTH_STA,
	WIPS_EID_MDK3_DEAUTH_STA,
	WIPS_EID_AIREPLAY_NG_DEAUTH_STA,
	WIPS_EID_DEASSO_STA,
	WIPS_EID_MDK3_DEASSO_STA,
	WIPS_EID_AUTH_FLOOD_STA,
	WIPS_EID_ASSO_FLOOD_STA,
	WIPS_EID_PROBE_FLOOD_STA,
	WIPS_EID_ASSO_FLOOD_ACK_STA,
	WIPS_EID_ASSO_FLOOD_RTS_STA,
	WIPS_EID_ASSO_FLOOD_CTS_STA,
	WIPS_EID_DURATION_ATTACK,
	WIPS_EID_TOOMANY_AP,
	WIPS_EID_BRAODCAST_STORM,
	WIPS_EID_BRAODCAST_SMAC,
	WIPS_EID_GROUP_SMAC,
	WIPS_EID_AP_TOOMANY_QBSSSTA,

	WIPS_EID_CRACK_GRP,//54
	WIPS_EID_VIOLENT_CRACK_STA,
	WIPS_EID_AIREPLAY_NG_FRAMG_STA,
	WIPS_EID_AIREPLAY_NG_CHOP_STA,
	WIPS_EID_AIREPLAY_NG_ARP_STA,
	WIPS_EID_WESSID_NG_STA,
//	WIPS_EID_ASLEAP_ATTACK,
	WIPS_EID_8021XAUTH_ATTACK,

	WIPS_EID_INFO_GRP,//61
	WIPS_EID_ASSO_DENIED_STA,
	WIPS_EID_AUTH_REFUSED,
	WIPS_EID_AP_SMALL_FRAG_PKG,
//	WIPS_EID_SMALL_INTERVAL_RETRY_PKG,
	WIPS_EID_TOOMANY_BEACON,
	WIPS_EID_REASSO_REFUSED,
//	WIPS_EID_SMALL_INTERVAL_RTS_CTS,
	WIPS_EID_AP_ESSID_DIFF,
	WIPS_EID_AP_BG_MODE,
	WIPS_EID_11N_DEVICE,
	WIPS_EID_AP_SUPPORT40MHZ,
	WIPS_EID_NO_QOS,
	WIPS_EID_AP_SIGNAL_TOOLOW,
	WIPS_EID_PROBE_NOAUTH,
	WIPS_EID_PROBE_REFUSED,
//	WIPS_EID_ROAMING_BIG_INTERVAL,
	WIPS_EID_STA_SMALL_FRAG_PKG,
//	WIPS_EID_STA_SLEEPING_BIG_INTERVAL,
	WIPS_EID_STA_LISTENINTERVAL_TOOBIG,
//	WIPS_EID_STA_SLEEPING_LOSE_PKG,
	WIPS_EID_STA_SIGNAL_TOOLOW,
//	WIPS_EID_WINDOWS_AUTO_WIRELESS_CONFIG,
	WIPS_EID_AP_GN_MODE,
	
	WIPS_EID_AUDIT_GRP,//79
	WIPS_EID_NEW_DEVICE_AP,
	WIPS_EID_NEW_DEVICE_STA,
	WIPS_EID_DEVICE_DOWN_AP,
	WIPS_EID_DEVICE_DOWN_STA,
	WIPS_EID_STA_ON_NETWORK,
	WIPS_EID_STA_OFF_NETWORK,
	WIPS_EID_NOASSO_DATA,
	WIPS_EID_AP_REBOOTED,
	WIPS_EID_WIRELESS_MOOCH,
	WIPS_EID_SWITCH_ESSID,
	WIPS_EID_SWITCH_BSSID,

	WIPS_EID_INTERFERENCE_GRP,//91
	WIPS_EID_FREQ_HARDWARE_ERR,
	WIPS_EID_FREQ_HARDWARE_ERR2OK,
	WIPS_EID_FREQ_OVERLAPPING,
//	WIPS_EID_SNR_TOOLOW,/* SNR : Signal to Noise Ratio*/
	WIPS_EID_INTERFERENCE,
	WIPS_EID_INTERFERENCE_2OK,
	WIPS_EID_SUPPRESSION,
	WIPS_EID_SUPPRESSION_2OK,
	WIPS_EID_BITRATE_CHANGED,
	WIPS_EID_RATESWITCH_TOOFAST,
	WIPS_EID_AP_TOOMANY_RETRY,
	WIPS_EID_STA_TOOMANY_RETRY,

	WIPS_EID_MAX,//103

	WIPS_EID_SIGNAL_TOOLOW,
	
	WIPS_EID_ACTION_GRP,
	WIPS_EID_STA_BLOCK_START,
	WIPS_EID_AP_BLOCK_START,
	WIPS_EID_STA_BLOCK_STOP,
	WIPS_EID_AP_BLOCK_STOP
};
#endif
struct event_pri{
	char *name;
	int    pri;
	char *meaning;
};

//static char dic_table[WIPS_EID_MAX][512] = {{'\0'}};

typedef struct event_pri EVENT_PRI;

static EVENT_PRI eve_pri_table[] = {
		{"全部", -1},//1
		{"错误配置类", -1, ""},//2
		{"未设置加密方式",2, "未设置加密方式的AP为开放系统，任何客户端均可访问"},
		{"加密方式为WEP",2, "WEP由于加密强度不够，是一种可以被轻易破解的加密方式"},
		{"WPS功能开启", 4, "WPS开启过程中，AP增加了受到黑客攻击的可能性"},
		{"AP开启WDS功能", 1, ""},
		{"STA开启WDS功能", 1, ""},
		{"Ad-hoc设备", 4,""},
		{"",1,""},
		{"",1,""},
//		{"",1,""},
		{"",1,""},
		{"",2,""},
//		{"",1,""},
		{"",5,""},
		{"",1,""},
		{"",1,""},
		{"",5,""},
		{"",2,""},
		{"",2,""},
		{"",1,""},
//		{"",2,""},
		{"",1,""},
		{"",1,""},
//		{"",5,""},
//		{"",5,""},
		{"无线扫描探测类", -1, ""},//22
//		{"空探测响应",5,""},
		{"发现未授权终端扫描无线网络",5,""},
		{" 无线欺骗类", -1,""},//24
		{"钓鱼AP",2,""},
		{"HotSpotter攻击",2,""},
		{"Airbase-ng fake ap",2,""},
		{"MDK3 FAKE AP 攻击",4,""},
		{"",2,""},
		{"",2,""},
		{"",5,""},
		{"",6,""},
		{"",5,""},
		{"",2,""},
//		{"",2,""},
		{"",6,""},
		{"",-1,""},//DOS ATTACK 36
		{"",1,""},
		{"",1,""},
		{"",1,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",5,""},
		{"",2,""},
		{"",5,""},
		{"",5,""},//END DOS ATTACK	
		{"",-1,""},//CRACK 54
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
		{"",2,""},
//		{"",2,""},
		{"",2,""},//END CRACK
		{"",-1,""},//wconfig 61
		{"",5,""},
		{"",5,""},
		{"",6,""},
//		{"",6,""},
		{"",6,""},
		{"",5,""},
//		{"",6,""},
		{"",5,""},
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",5,""},
		{"",5,""},
//		{"",6,""},
		{"",6,""},
//		{"",6,""},
		{"",6,""},
//		{"",6,""},
		{"",6,""},
//		{"",5,""},
		{"",5,""},//end wconfig
		{"",-1,""},//audit 79
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",6,""},
		{"",5,""},
		{"",6,""},
		{"",5,""},
		{"",6,""},
		{"",6,""},//end audit
		{"",-1,""},//noise 91
		{"",5,""},
		{"",5,""},
		{"",5,""},
//		{"",5,""},
		{"",5,""},
		{"",5,""},
		{"",5,""},
		{"",5,""},
		{"",5,""},
		{"",5,""},
		{"",5,""},
		{"",5,""},//end noise
		{"",-1,""},//MAX
		{"无线信号低",5,"无线信号低"},
		{"系统关联动作类",-1,""},//ACTION_GRP
		{"开始阻断STA",LOG_INFO,"开始阻断STA"},
		{"开始阻断AP",LOG_INFO,"开始阻断AP"},
		{"停止阻断STA",LOG_INFO,"停止阻断STA"},
		{"停止阻断AP",LOG_INFO,"停止阻断AP"},	
		{NULL,-1, NULL}
};

#ifndef HAVE_SYSLOG_H
#define LOG_PRIMASK     0x07    /* mask to extract priority part (internal) */
                                /* extract priority */
#define LOG_PRI(p)      ((p) & LOG_PRIMASK)
#define LOG_MAKEPRI(fac, pri)   (((fac) << 3) | (pri))
#endif



#define MAX_LOG_SIZE 2048
#define FORMAT_STRING "%s=%s "
#define FORMAT_DIGITAL "%s=%d "
#define FMT(x) ((x == STRING)?FORMAT_STRING:FORMAT_DIGITAL)

struct log_buf {
	char *buf;
	unsigned int offset;
	unsigned int len;
};

static inline int log_buf_init(struct log_buf *buf)
{
	buf->buf = XCALLOC(MTYPE_WIPS_DEBUG_LOG,MAX_LOG_SIZE);
	if (!buf->buf)
		return -1;
	
	buf->offset = 0;
	buf->len = MAX_LOG_SIZE -1;

	return 0;
}

#define IN
#define OUT

#define AP 		1<<0
#define STA		1<<1
#define ADHOC	1<<2
#define WDS		1<<3

#define GET_DEV_ETH0_MAC 	"ifconfig | grep eth0 | awk '{print $5}'"
#define GET_DEV_ETH0_IP     	"ifconfig eth0 | grep 'inet addr' | awk '{print $2}' | awk -F ':' '{print $2}'"


#if 0
#define MAX_LOG_SIZE 1024
static inline void  lfd_log(CLIENTContext *c, const char *fmt, ...)
{
	va_list ap;
	int len;	
	char *buf = c->sbuf;

	va_start(ap, fmt);

	len = vsnprintf(buf, IOBUFSIZE, fmt, ap);
	buf[len] = '\0';
	
	va_end(ap);
}
#endif
#endif
