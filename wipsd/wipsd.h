#ifndef _H_WIPSD
#define _H_WIPSD

#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/types.h>
#include <pthread.h>

#define WIPSD_SOCKET_PORT			13524

#define WIPSD_BLOCK_BY_DEAUTH 	1
#define WIPSD_BLOCK_BY_ARP		2
#define NO_USE_CODE 				0

typedef struct
{
	unsigned char version:2; /*bit*/
	unsigned char type:2;
	unsigned char subtype:4;
	unsigned char toDS:1;
	unsigned char fromDS:1;
	unsigned char morefrag:1;
	unsigned char retry:1;
	unsigned char pwr:1;
	unsigned char moredata:1;
	unsigned char wep:1;
	unsigned char rsvd:1;
}
frame_control_t;

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
};

typedef struct
{
//  __u16 frame_control __attribute__ ((packed));
	__u8 frame_control[2];//__attribute__ ((packed));
	__u16 duration_id __attribute__ ((packed));
	__u8 mac1[6];//__attribute__ ((packed));
	__u8 mac2[6];//__attribute__ ((packed));
	__u8 mac3[6];//__attribute__ ((packed));
	__u16 sequence __attribute__ ((packed));
	__u8 mac4[6];// __attribute__ ((packed));
	__u32 ssid_len;
	__u8 SSID[SSID_BUFSIZE_D];
	struct tm *timep;
	struct timeval ts;
	__u16 status_code;
	__u8 status_code_str[180];
	__u16 aid		;
	__u8 auth_str[20];
}wipsd_hdr_t;

#define PACKAGELENGTH 200
typedef struct wipsd_block_list
{
	struct wipsd_block_list * next;
	struct w_node_list * beacon;
	struct w_node_list * sta;
	long stopDuration;//Block length (s)
	long sentPacNumb;
	__u8 forced;//0:non used  1:forced blocking  2:forced no blocking  3:send a blocking package at once  4~255:Reservations
	__u8 activity;//Blocking the transmission in activity time when sniffed the device.
	__u8 interval;
	__u8 type;
	short pacLength;// __attribute__ ((packed));
	__u8 buf[PACKAGELENGTH];
}wipsd_block_list;


#define BEACON_CHECK_IDENTICAL	0
#define BEACON_CHECK_NEWCASE	1
#define BEACON_CHECK_NO_LIST	2
#define BEACON_CHECK_MODIFYCASE	3

#define ELEMENT_ID_SSID		0
#define ELEMENT_ID_RATES	1
#define ELEMENT_ID_DS		3
#define ELEMENT_ID_TIM		5
#define ELEMENT_ID_COUNTRY	7
#define ELEMENT_ID_ERP		42
#define ELEMENT_ID_HTCAPA	45
#define ELEMENT_ID_RSN		48
#define ELEMENT_ID_EXRATES	50
#define ELEMENT_ID_HTINFO	61
#define ELEMENT_ID_VHTCAP   191
#define ELEMENT_ID_VHTOP    192
#define ELEMENT_ID_VENDOR	221

/* Some usefull constants */
#define KILO	1e3
#define MEGA	1e6
#define GIGA	1e9

/* Basic operations */
#define SIOCSIWNAME	0x8B00		/* Unused */
#define SIOCGIWNAME	0x8B01		/* get name == wireless protocol */
#define SIOCSIWNWID	0x8B02		/* set network id (the cell) */
#define SIOCGIWNWID	0x8B03		/* get network id */
#define SIOCSIWFREQ		0x8B04		/* set channel/frequency (Hz) */
#define SIOCGIWFREQ		0x8B05		/* get channel/frequency (Hz) */
#define SIOCSIWMODE	0x8B06		/* set operation mode */
#define SIOCGIWMODE	0x8B07		/* get operation mode */
#define SIOCSIWSENS		0x8B08		/* set sensitivity (dBm) */
#define SIOCGIWSENS		0x8B09		/* get sensitivity (dBm) */

#define SIOCSIWRATE				0x8B20  /* set default bit rate (bps) */
#define IW_BITRATE_UNICAST		0x0001  /* Maximum/Fixed unicast bitrate */
#define IW_BITRATE_BROADCAST	0x0002  /* Fixed broadcast bitrate */

enum {
	LIST_TASK_ADD2APLIST,
	LIST_TASK_ADD2STALIST,
	LIST_TASK_CHECKWLIST,
	LIST_TASK_GETAPWLIST,
	LIST_TASK_GETSTAWLIST,
	LIST_TASK_GETWNODE,
	LIST_TASK_UPDATE_WPOLICY,
	LIST_TASK_APSTA,
	LIST_TASK_TCPAP2AC,
	LIST_TASK_ADDSSID,
	
	LIST_TASK_TREE_AP_SSID_CHANGE,
	LIST_TASK_TREE_AP_CHANNEL_CHANGE,
	LIST_TASK_TREE_STA_BSSID_CHANGE,
	LIST_TASK_TREE_STA_CHANNEL_CHANGE,
	
	LIST_TASK_TREE_GET_ESSID_NAME_ID,
	LIST_TASK_TREE_GET_BY_ESSID_ID,
	LIST_TASK_TREE_GET_BY_A_ESSID,
	LIST_TASK_TREE_GET_ALL_ESSID,
	LIST_TASK_TREE_GET_BY_CHANNEL,
	LIST_TASK_TREE_GET_ALL_CHANNEL,
	LIST_TASK_TREE_GET_ISLANDSTA_BY_CHANNEL,
	LIST_TASK_TREE_GET_ISLANDSTA_ALL_CHANNEL,
	LIST_ATTACK,
	LIST_TASK_TREE_BLOCK_WITH_A_ESSID,
	BLOCK_TASK_ADD_NODE,
	BLOCK_TASK_DEL_NODE,
	LIST_TASK_CREATE_FAKE_AP,
	LIST_TASK_DELETE_FAKE_AP,
	
	NO_ADD_NODE
};
#if 0
/*
 *	A frequency
 *	For numbers lower than 10^9, we encode the number in 'm' and
 *	set 'e' to 0
 *	For number greater than 10^9, we divide it by the lowest power
 *	of 10 to get 'm' lower than 10^9, with 'm'= f / (10^'e')...
 *	The power of 10 is in 'e', the result of the division is in 'm'.
 */
struct	iw_freq
{
	__u32		m;		/* Mantissa */
	__u16		e;		/* Exponent */
	__u8		i;		/* List index (when in range struct) */
};

struct	iw_param
{
  __s32		value;		/* The value of the parameter itself */
  __u8		fixed;		/* Hardware should not use auto select */
  __u8		disabled;	/* Disable the feature */
  __u16		flags;		/* Various specifc flags (if any) */
};

struct	iwreq
{
	union
	{
		char	ifrn_name[IFNAMSIZ];	/* if name, e.g. "eth0" */
	} ifr_ifrn;

	/* Data part */
	union
	{
		/* Config - generic */
		char		name[IFNAMSIZ];
		/* Name : used to verify the presence of  wireless extensions.
		 * Name of the protocol/provider... */

		struct iw_param	nwid;	/* network id (or domain - the cell) */
		struct iw_param	sens;		/* signal level threshold */
		struct iw_freq	freq;	/* frequency or channel :
					 * 0-1000 = channel
					 * > 1000 = frequency in Hz */
		struct iw_param	bitrate;	/* default bit rate */
		struct iw_param	txpower;	/* default transmit power */
		struct iw_param	rts;		/* RTS threshold threshold */
		struct iw_param	frag;		/* Fragmentation threshold */

		struct iw_param	power;		/* PM duration/timeout */
	}	u;
};
#endif
typedef struct
{
	__u8 fc[2];//
	__u8 du[2];//
	__u8 ds[6];//
	__u8 sa[6];//
	__u8 bssid[6];//
	__u8 sc[2];//
	__u8 reason_code[2];//
}deauthenticate_type;

typedef struct
{
	//802.11mac
	__u8 fc[2];//
	__u8 du[2];//
	__u8 mac1[6];//
	__u8 mac2[6];//
	__u8 mac3[6];//
	__u8 sc[2];//
  //  __u8 qos[2];//
	//LLC
	__u8 LLC[3]; // aa aa 03
	//SNAP
	__u8 vendor[3]; //00 00 00
	__u8 protocol[2]; //08 06
	//ARP
	__u8 hardware[2];  // 00 01
	__u8 protocol2[2];  // 08 00
	__u8 hwaddrlen; //6
	__u8 pcaddrlen; //4
	__u8 operation[2]; //arp request/response
	__u8 srchwaddr[6];
	__u8 srcpcaddr[4]; //ip
	__u8 dsthwaddr[6];
	__u8 dstpcaddr[4];
	__u8 fcs[4]; //00 00 00 00
} arp_type;

#define WEVENT_NAME_LEN 128
#define WEVENT_NAME_LEN_L (WEVENT_NAME_LEN - 1)
typedef struct wpolicy_struct
{
	int wpid;
	int weid;
	int channel;

	char wnet[SSID_BUFSIZE_D];
	char ap_name[64];
	char ap_mac[32];
	char sta_name[64];
	char sta_mac[32];
	char wevent[WEVENT_NAME_LEN];
	char sta_mac_mask[8];
	char ctime[32];
	char waction[8];
	char enable[8];
	char reverve[8];
	char vendor[128];
}wpolicy_struct;

typedef struct wevent_struct
{
	__u32 id;
	__u32 is_grp;
	__u32 grp_id;
	__u32 rev;

	char pri[8];
	char name[WEVENT_NAME_LEN];
	char cmd_name[WEVENT_NAME_LEN];

	__u32 count;

}wevent_struct;

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
	char sec_type[16];
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
}ap_node;

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
}sta_node;


#define BLOCK_LIST_MAX_NUM_2G   14
#define BLOCK_LIST_MAX_NUM_5G   42
#define BLOCK_LIST_MAX_NUM      200


typedef struct block_sta_node
{
	struct block_sta_node *prev;
	struct block_sta_node *next;
	struct block_sta_node *head;
	struct block_sta_node *tail;
	char mac[24];
	char bssid[24];
	int channel;
	int hit;
	int auxiliary_channel;
	__u8 addr_ipv4[4];
	__u8 gate_mac[6];
	__u8 gate_ip[6];
	__u8 block_method;
  __u32 block_count;
} block_sta_node;


#define CREATE_AP_LIST "create table beacon_test1( ssid nvarchar( 30 ), mac nvarchar( 24 ), interval varchar( 4 ), \
g_rates varchar( 4 ), n_rates varchar( 4 ), single varchar( 4 ), noise varchar( 4 ), channel varchar( 4 ), \
sec_type nvarchar( 40 ), ipaddr nvarchar( 16 ), vendor nvarchar(128), osf nvarchar( 30 ), osg nvarchar( 30 ), \
alert nvarchar( 30 ), up_time TIMESTAMP default (datetime('now', 'localtime')), last_time TIMESTAMP, \
name nvarchar(32), type nvarchar(8), mmac nvarchar(24), bridge nvarchar(4), bind nvarchar(4) , permit nvarchar(4) )"

#define SELECT_AP_LIST  "select * from beacon_test1"

#define DROP_AP_LIST	"drop table beacon_test1"

#define INSERT_AP_LIST  "insert into beacon_test1 (\
\"ssid\",\"mac\",\"interval\",\"g_rates\",\"n_rates\",\"single\",\"noise\",\
\"channel\",\"sec_type\",\"ipaddr\",\"vendor\",\"up_time\") SELECT \"%s\",\"%02x:%02x:%02x:%02x:%02x:%02x\",\
\"%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"%d\",\"%s\",\"%s\",\"%s\", (datetime('now', 'localtime')) \
WHERE NOT EXISTS (SELECT 1 FROM beacon_test1 WHERE mac = '%02x:%02x:%02x:%02x:%02x:%02x')"


#define UPDATE_AP_LIST  "update beacon_test1 set ssid=\"%s\", interval=\"%d\", \
g_rates=\"%d\", n_rates=\"%d\", single=\"%d\", noise=\"%d\", channel=\"%d\", sec_type=\"%s\", \
ipaddr=\"%s\",vendor=\"%s\",last_time=(datetime('now', 'localtime'))  where mac=\"%02x:%02x:%02x:%02x:%02x:%02x\" "


/*========================================================================================*/

#define CREATE_STA_LIST "create table sta_list( ssid nvarchar( 30 ),mac nvarchar( 24 ), bssid nvarchar( 24 ), \
rates varchar( 4 ), single varchar( 4 ), noise varchar( 4 ), channel varchar( 4 ), ipaddr nvarchar( 16 ), vendor nvarchar(128), \
osf nvarchar( 30 ), osg nvarchar( 30 ), alert nvarchar( 30 ), up_time TIMESTAMP default (datetime('now', 'localtime')), \
last_time TIMESTAMP, name nvarchar(32), type nvarchar(8), mmac nvarchar(24), bridge nvarchar(4), bind nvarchar(4) , \
permit nvarchar(4) )"

#define SELECT_STA_LIST "select * from sta_list"

#define DROP_STA_LIST   "drop table sta_list"

#define INSERT_STA_LIST "insert into sta_list (\"ssid\",\"mac\",\"bssid\",\"rates\",\"single\",\
\"noise\",\"channel\",\"ipaddr\",\"vendor\", \"up_time\") SELECT \"%s\",\"%02x:%02x:%02x:%02x:%02x:%02x\",\
\"%02x:%02x:%02x:%02x:%02x:%02x\",\"%d\",\"%d\",\"%d\",\"%d\" ,\"%s\",\"%s\",(datetime('now', 'localtime')) \
WHERE NOT EXISTS (SELECT 1 FROM sta_list WHERE mac = '%02x:%02x:%02x:%02x:%02x:%02x')"

#define UPDATE_STA_LIST "update sta_list set ssid=\"%s\", bssid=\"%02x:%02x:%02x:%02x:%02x:%02x\", \
rates=\"%d\", single=\"%d\", noise=\"%d\", channel=\"%d\",ipaddr=\"%s\",vendor=\"%s\", last_time=(datetime('now', 'localtime')) \
where mac=\"%02x:%02x:%02x:%02x:%02x:%02x\" "

#define UPDATE_STA_WEVENT "update sta_list set alert=\"%s\", permit=\"%d\", last_time=(datetime('now', 'localtime')) where mac=\"%s\" "
#define UPDATE_AP_WEVENT "update beacon_test1 set alert=\"%s\", permit=\"%d\", last_time=(datetime('now', 'localtime')) where mac=\"%s\" "

/*========================================================================================*/

#define CREATE_MANAGEMENT_LIST "create table management( M_type nvarchar( 30 ), d_mac nvarchar( 17 ),\
s_mac nvarchar( 17 ), bssid nvarchar( 17 ), body varchar( 4 ),ssid nvarchar( 30 ), \
firsttime TIMESTAMP default (datetime('now', 'localtime')),lasttime TIMESTAMP )"

#define SELECT_MANAGEMENT_LIST "select * from management"

#define DROP_MANAGEMENT_LIST "drop table management"

#define INSERT_MANAGEMENT_LIST	  "insert into management (\
\"M_type\",\"d_mac\",\"s_mac\",\"bssid\",\"body\",\"ssid\") \
values (\"%s\",\"%02x:%02x:%02x:%02x:%02x:%02x\",\
\"%02x:%02x:%02x:%02x:%02x:%02x\",\"%02x:%02x:%02x:%02x:%02x:%02x\",\
\"%d\",\"%s\")"




/*========================================================================================*/

extern int check_stalist(w_node_list ** header, w_node_list ** tail,struct w_node * node);
extern int check_wlist(w_node_list ** header, w_node_list ** tail,ListBuf * treebuf);
int ussleep(long us);

#endif
