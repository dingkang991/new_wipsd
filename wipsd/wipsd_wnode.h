#ifndef _H_WIPSD_WNODE
#define _H_WIPSD_WNODE

#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/types.h>
#include <pthread.h>
#include <stdint.h>
#include "debug.h"

#define SSID_BUFSIZE	63
#define SSID_BUFSIZE_D	(SSID_BUFSIZE+1)
#define SSID_MAX_NUM    256

#define wipsd_free(ptr) do{ if(ptr){ DRL(DL_MEM, 2,"free mem!"); free(ptr); ptr=NULL; } }while(0)
#define wipsd_sqlite3_close(ptr) do{ if(ptr){ DRL(DL_DB, 2, "close db!"); sqlite3_close(ptr); ptr=NULL; } }while(0)

#define swap16(A)	do{ union w{  int a;char b;}c; c.a = 1;if(c.b !=1){ \
						((__u8*)&A)[0] ^= ((__u8*)&A)[1];\
						((__u8*)&A)[1] ^= ((__u8*)&A)[0];\
						((__u8*)&A)[0] ^= ((__u8*)&A)[1]; } }while(0)
#define swap32(A)	do{ union w{  int a;char b;}c; c.a = 1;if(c.b !=1){ \
						((__u8*)&A)[0] ^= ((__u8*)&A)[3];\
						((__u8*)&A)[3] ^= ((__u8*)&A)[0];\
						((__u8*)&A)[0] ^= ((__u8*)&A)[3];\
						((__u8*)&A)[1] ^= ((__u8*)&A)[2];\
						((__u8*)&A)[2] ^= ((__u8*)&A)[1];\
						((__u8*)&A)[1] ^= ((__u8*)&A)[2]; } }while(0)
#define swap64(A)	do{ union w{  int a;char b;}c; c.a = 1;if(c.b !=1){ \
						((__u8*)&A)[0] ^= ((__u8*)&A)[7];\
						((__u8*)&A)[7] ^= ((__u8*)&A)[0];\
						((__u8*)&A)[0] ^= ((__u8*)&A)[7];\
						((__u8*)&A)[1] ^= ((__u8*)&A)[6];\
						((__u8*)&A)[6] ^= ((__u8*)&A)[1];\
						((__u8*)&A)[1] ^= ((__u8*)&A)[6];\
						((__u8*)&A)[2] ^= ((__u8*)&A)[5];\
						((__u8*)&A)[5] ^= ((__u8*)&A)[2];\
						((__u8*)&A)[2] ^= ((__u8*)&A)[5];\
						((__u8*)&A)[3] ^= ((__u8*)&A)[4];\
						((__u8*)&A)[4] ^= ((__u8*)&A)[3];\
						((__u8*)&A)[3] ^= ((__u8*)&A)[4]; } }while(0)

#undef FALSE
#undef TRUE

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define WIPS_NAME_ACTION_GRP "系统关联动作类"
#define WIPS_NAME_STA_BLOCK_START "开始阻断STA"
#define WIPS_NAME_AP_BLOCK_START "开始阻断AP"
#define WIPS_NAME_STA_BLOCK_STOP "停止阻断STA"
#define WIPS_NAME_AP_BLOCK_STOP "停止阻断AP"

#define WIPS_EID_MIN 1


typedef struct wips_event
{
	int	eventid;
	char *name;
}wips_event;


extern wips_event wips_event_table[];

enum {
	WIPS_EID_ALL = WIPS_EID_MIN,

	WIPS_EID_ERR_CFG_GRP,
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

	WIPS_EID_PROBE_GRP,
//	WIPS_EID_NULLPROBE_RESP,
	WIPS_EID_UNAUTHSTA_PROBE_TOOMANY,

	WIPS_EID_SPOOFING_GRP,
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

	WIPS_EID_DOS_GRP,
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

	WIPS_EID_CRACK_GRP,
	WIPS_EID_VIOLENT_CRACK_STA,
	WIPS_EID_AIREPLAY_NG_FRAMG_STA,
	WIPS_EID_AIREPLAY_NG_CHOP_STA,
	WIPS_EID_AIREPLAY_NG_ARP_STA,
	WIPS_EID_WESSID_NG_STA,
//	WIPS_EID_ASLEAP_ATTACK,
	WIPS_EID_8021XAUTH_ATTACK,

	WIPS_EID_INFO_GRP,
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
	
	WIPS_EID_AUDIT_GRP,
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

	WIPS_EID_INTERFERENCE_GRP,
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

	WIPS_EID_MAX,

	WIPS_EID_SIGNAL_TOOLOW,
	
	WIPS_EID_ACTION_GRP,
	WIPS_EID_STA_BLOCK_START,
	WIPS_EID_AP_BLOCK_START,
	WIPS_EID_STA_BLOCK_STOP,
	WIPS_EID_AP_BLOCK_STOP
};

typedef struct blocked_bssid
{
	struct blocked_bssid * next;
	__u8 bssid[6];//MAC
}blocked_bssid;

/*
 * NB: we allocate the max space required for the TIM bitmap.
*/
struct w_node
{
	int64_t signal_cum;
	uint64_t timestamp;
	long long data_mum;
	struct wipsd_interface *wipsd_itf;
	struct sockaddr_in addr;
	char vendor[128];
	char sec_type[48];//WPA/RSN parameters
	char ipv4[24];
	char ssid[SSID_BUFSIZE_D];//ssid
	char probe_ssid[SSID_BUFSIZE_D];//ssid
	char name[SSID_BUFSIZE_D];//ssid
	char ssid2[2];//ssid
	char ssid3[2];//ssid
	char ssid4[2];//ssid
	char ssid5[2];//ssid
	char ssid6[2];//ssid
	char ssid7[2];//ssid
	char ssid8[4];//ssid

	struct w_node *ssidtree_root;
	struct w_node *ssidtree_lastap;
	struct w_node *ssidtree_pap;
	struct w_node *lastap;
	struct w_node *pap;
	struct w_node *laststa;
	struct w_node *psta;
	blocked_bssid * blocked_ap;

#define ALERT_LEN 5
	__u32 alert[ALERT_LEN];
	__u32 beacon_c;
	
	time_t up_time;
	time_t last_time;

	int signal_con;
	int signal_average;
	int beaconc_c;
	int beaconc_t;
	time_t refresh_time;
	int linked_c;
	int linked_t;
	int link_changed;
	int channel_changed;
	__u32 dataframe_count;
	
	int deauth_c;
	int deauth_c_crack;
	int deauth_t;
	int auth_c;
	int auth_c_crack;
	int auth_t;
	int deassoc_c;
	int deassoc_t;
	
	int assoc_c;
	int assoc_t;
	int arp_c;
	int arp_t;
	int ack_c;
	int ack_t;
	int rts_c;
	int rts_t;
	
	int cts_c;
	int cts_t;
	int prob_req_c;
	int prob_req_t;
	int retry_c;
	int retry_t;
	int ssid1_AgingTime;
	int ssid2_AgingTime;
	
	int ssid3_AgingTime;
	int ssid4_AgingTime;
	int ssid5_AgingTime;
	int ssid6_AgingTime;
	int ssid7_AgingTime;
	int ssid8_AgingTime;
	int ssidn_type;//bit 0:ap 1:sta
	int rate_cum;
	
	int rate_con;
	int rate_average;
	int rate_t;
	int rate_change;
	int rate_times;
	int reasso_time;
	int wpa_time;
	int auth_time;
	
	int probe_req_time;
	int probe_noauth_time;
	int auth8021X_c;
	int auth8021X_t;
	int signal;
	int noise;
	__u32 channel;
	__u32 rates;//extended supported rates

	__u16 capability_info;
	__u16 interval;//beacon or listen inerval
	__u16 reason_code;
	__u16 id;
	__u16 block;
	__u16 duration;
	__u16 sequence_num;
	__u16 rev1;

	__u8 bssid[6];//MAC
	__u8 pro_bssid[6];//MAC
	__u8 mac[6];//MAC
	__u8 dstmac[6];//MAC
	__u8 lan_mac[6];//MAC
	__u8 essid_id[6];//MAC
	__u8 ssid_len;//ssid_len_FN
	__u8 prober_mac[6]; //增加探针源mac地址
	__u8 b_rates;//extended supported rates

	__u8 g_rates;//extended supported rates
	__u8 n_rates;
    __u8 phy_mode;// 802.11 a/b/g/n/ac
    __u8 is_assoc2ap;
	__u8 n_20and40;//HT Capabilities
	__u8 node_type;//bit0:ap  bit1:sta  bit2:ad-hoc  bit3:wds bit4:aplist(0)/stalist(1)  bit5:wps bit6:Unauthorize(0)/Authorize(1) bit7&bit8:External(00)/Internal( 1[^7]  0[^8])/RogueAP( 0[^7]  1[^8])
	__u8 internal_node;
    __u8 is_arp_added;
	__u8 nat_dev;
	__u8 sta_num;
	__u8 sta_number;
	__u8 authed;		//1//authed:1, unauthed:others

	__u8 hide_ssid;
	__u8 block_method;
	__u8 last_pkg_type;
	__u8 open_qos;
	__u8 reasso_mark;
	__u8 wpa8021x_mark;
	__u8 probe_req_mark;
	__u8 probe_noauth_mark;
	
	__u8 auth_mark;
	__u8 child_num;
	__u8 freq_band;

	__u8 addr_ipv4[4];
	__u8 gatemac[6];
 	 __u16 is_null_data;
	__u8 block_func;
	__u16 net_type;
	__u32 data_channel;

	long send_info_timeout;
} ;

enum ieee80211_phymode {
    IEEE80211_MODE_AUTO,
    IEEE80211_MODE_11A, 
    IEEE80211_MODE_11B,
    IEEE80211_MODE_11G, 
    IEEE80211_MODE_11NA, 
    IEEE80211_MODE_11NG, 
    IEEE80211_MODE_11AC,
};

#define IEEE80211_RATE_MAXSIZE  36  /* max rates we'll handle */

struct ieee80211_rateset{
    u8 rs_nrates;
    u8 rs_rates[IEEE80211_RATE_MAXSIZE];
};

struct ieee80211_ie_header {
    u8 element_id;     /* Element Id */
    u8 length;         /* IE Length */
};

enum{
	WIPS_PKGTYPE_DEFAULT = 1,
	WIPS_PKGTYPE_DATA,
	WIPS_PKGTYPE_DEAUTH,
	WIPS_PKGTYPE_DEASS
};

typedef struct w_node_list
{
	struct w_node_list * next;
	struct w_node_list * last;
	pthread_mutex_t list_lock;
	struct w_node b_frame;
}w_node_list;

struct w_ssid
{
	char ssid[SSID_BUFSIZE_D];
	 __u32 type;					/* in_ap:1, ex_ap:2 */
	struct w_node *pap;			/* pointer to the ap belong this ssid */
};

struct list_tast
{
	struct list_tast *next;
	int task_type;
	void *node;
};
void insertListTask(struct list_tast *mp);

#define LISTBUF_MAX (sizeof(struct w_node)*200)
typedef struct
{
	int len;// __attribute__ ((packed));
	__u8 buf[LISTBUF_MAX];
}ListBuf;



typedef struct nodeInfo
{
	__u32 node_type;//bit0:ap  bit1:sta  bit2:ad-hoc  bit3:wds bit4:aplist(0)/stalist(1)  bit5:wps bit6:Unauthorize(0)/Authorize(1) bit7&bit8:External(00)/Internal( 1[^7]  0[^8])/RogueAP( 0[^7]  1[^8])
	char ipv4[24];
	__u8 mac[6];//MAC
	char name[SSID_BUFSIZE_D];
}nodeInfo;

typedef struct nodeInfo_exec_hook_para
{
	void * node;
	int * i;//MAC
}nodeInfo_exec_hook_para;

#define BLOCKING_FIXED_RATE 9

#define CHANNEL_MIN_2G 1
#define CHANNEL_MAX_2G 14	//13
#define CHANNEL_MIN_5G 15	//149
#define CHANNEL_MAX_5G 56	//27	//165

#define PKT_MON_GAP 200

//#define X86_FINDIP 0
#define WIPS_PKT_MAX_LEN	2048

typedef struct essidObject
{
	char name[SSID_BUFSIZE_D];//ssid
	char type[20];
	char auth[44];//WPA/RSN parameters
	char mode[20];
	char wtm1[10];
	char wtm2[10];
	__u32 start_h, start_m, start, end_h, end_m, end;
	char ip[16];
	char mac[20];
}essidObject;

typedef struct ctimeObject {
	char name[SSID_BUFSIZE_D];
	__u16 n_type;
	__u16 week;
	__u32 start_h, start_m, start, end_h, end_m, end;
	__u32 except_start_h, except_start_m, except_start, except_end_h, except_end_m, except_end;
}ctimeObject;

#define AIRODUMP_NG	\
		"\x00\x00\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define AIRODUMP_NG_e\
		"\x00\x00\x01\x08\x02\x04\x0B\x16\x0C\x12\x18\x24\x32\x04\x30\x48\x60\x6C"

#define MDK3_BEACON	\
		"\x05\x04\x00\x01\x00\x00"
//		"\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x01\x00"
/*
typedef struct nodeInfo_2beBlock
{
	char mac[20];
	char bssid[20];
	int channel;
	__u8 freq_band;
	__u8 ipv4[4];
}nodeInfo_2beBlock;
*/
typedef struct nodeInfo_2beBlock
{
	__u8 mac[6];
	__u8 bssid[6];
	int channel;
	__u8 wgate_mac[6];	
	__u8 freq_band;
	__u8 block_method; //bit0:deauth, bit1:arp, ...
	__u8 ipv4[4];
	__u8 wgate_ipv4[4];
}nodeInfo_2beBlock;

/*========================================================================================*/

//#define DB_FILE "/usr/local/etc/wips/beacon_test.db"
#define WIPS_LOG_DB "/usr/local/etc/wips/wips_log.db"
#define WIPS_WCONFIG_DB "/usr/local/etc/wips/wconfig.db"

#if 0
#define WIPS_DEBUG_INFO "/usr/hls/etc/wdebug.info"
#endif
/*========================================================================================*/

#endif
