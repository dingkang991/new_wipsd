#ifndef __TOS_CONFIG_HHH_
#define __TOS_CONFIG_HHH_

#include <linux/types.h>



#ifndef __KERNEL__
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ulist.h"

#define atomic_t unsigned int


#ifndef __NR_hls_config
#define __NR_hls_config (__NR_Linux + 304)
//#define __NR_hls_config 297 

#endif

#else
#include <linux/slab.h>
#include <linux/rcupdate.h>
#endif



#define OBJ_TYPE_MMIN                1
#define OBJ_TYPE_MMAX                32


#define OBJ_TYPE_GROUP_ADDRESS       1
#define OBJ_TYPE_ADDRESS             2 /* ADDRESS must be bigger than GROUP ADDRESS!! */
#define OBJ_TYPE_SCHEDULE            3
#define OBJ_TYPE_QOSCLASS            4      
#define OBJ_TYPE_CAPP                5      
#define OBJ_TYPE_URL                 6
#define OBJ_TYPE_FILE                7

#define OBJ_TYPE_POLICY              10


#define OBJ_TYPE_SMIN                128
#define OBJ_TYPE_SMAX                160


#define OBJ_TYPE_LOG                 129
#define OBJ_TYPE_DEV_NAME            130
#define OBJ_TYPE_SNMP                131
#define OBJ_TYPE_NTPSERVER           132
#define OBJ_TYPE_NTPCLIENT           133
#define OBJ_TYPE_HA                  134
#define OBJ_TYPE_LIC_INFO            135
#define OBJ_TYPE_DNS                 136
#define OBJ_TYPE_IF_BRIDGE           137
#define OBJ_TYPE_IF_ETHER            138
#define OBJ_TYPE_TIMEZONE            139
#define OBJ_TYPE_NETFLOW	         140
#define OBJ_TYPE_RULES_UPDATE		 141
#define OBJ_TYPE_AUTH_ACCESS_PERMIT		142
#define OBJ_TYPE_SERNO_INFO 143
#define OBJ_TYPE_HDISK_THRESHOLD 144



#define CMD_TYPE_MIN                 1
#define CMD_TYPE_MAX                 18


#define CMD_TYPE_ADD                 1
#define CMD_TYPE_DEL                 2
#define CMD_TYPE_MODIFY              3
#define CMD_TYPE_MOVE                4
#define CMD_TYPE_SHOW                5
#define CMD_TYPE_GETNUM              6
#define CMD_TYPE_MATCH               7
#define CMD_TYPE_SETMAXID            8
#define CMD_TYPE_NEWMAXID            9
#define CMD_TYPE_FLUSH               10
#define CMD_TYPE_RENAME              11
#define CMD_TYPE_IMPLEMENT           12
#define CMD_TYPE_GETMAXID            13
#define CMD_TYPE_SETID_FROMTP        14
#define CMD_TYPE_REFER_GETNUM        15
#define CMD_TYPE_REFER               16
#define CMD_TYPE_SETMAXID2           17
#define CMD_TYPE_RESETID_FORTP       18
#define CMD_TYPE_CLONE_OBJ	         19
#define MIN_USERID                   500000


#define STAT_TYPE_DEFINE			0
#define STAT_TYPE_PF				1
#define STAT_TYPE_DPI				2
#define STAT_TYPE_FIREWALL			3
#define STAT_TYPE_NAT				4
#define STAT_TYPE_AVSE				5
#define STAT_TYPE_VPN				6

#define STAT_TYPE_NUM				7





enum {
	ERR_BEGIN = 100,	
	ERR_CONFIG,
	ERR_ID_EXIST,
	ERR_ID_NEXIST,
	ERR_NAME_RESERVED,
	ERR_NAME_EXIST,
	ERR_NAME_NEXIST,
	ERR_ID2_NEXIST,
	ERR_INVALID_CMD,
	ERR_MISMATCH,
	ERR_REFERED,
	
	ERR_NOMEM,
	ERR_ARGUMENT,
	ERR_BUFLACK,
	ERR_REFER_NEXIST,
	ERR_MANY_REFERS,
	ERR_ID_MISMATCH,
	ERR_SAME_OBJ,
	ERR_OBJ_MAX,
	ERR_OBJ_TYPE_MAX,
	ERR_ID_REDUP,
	ERR_NAME_LEN,

	ERR_OPEN_FILE,

	ERR_OPEN_RESOLV_CONF,
	ERR_MANY_DNS,
	
	ERR_PRETREAT_NULL,
	ERR_PRETREAT_LINE_LEN,
	ERR_PRETREAT_WORD_LEN,
	ERR_PRETREAT_WORD_NUM,
	ERR_PRETREAT_MULTI_STRING,
	ERR_PRETREAT_MSTR_LEN,

	ERR_PARAM,
	ERR_NO_CMD,
	ERR_FILE,
};


//added by cp
#define MAX_ADDR_GRP_NUM	32

#define MAX_REFER_NUM	32
#define MAX_NAME_LENGTH	32
#define MAX_NAME_LENGTH_INTERNAL 40

#define MAX_BRIDGE_NUM 8
#define MAX_INTERFACE_NUM 16

#define	IN_WORD_NUM	64
#define	IN_LINE_LEN	65534


#define	POPEDOM_SUPER	0x0001
#define	POPEDOM_READ	0x0002
#define	POPEDOM_WRITE	0x0004
#define	POPEDOM_GUI		0x0100
#define	POPEDOM_CLI		0x0200
#define	POPEDOM_HA		0x1000
#define	POPEDOM_ALL		0xffff





#define ROOT_VS_ID	0


struct hls_obj_head
{
	struct list_head list;
	struct hlist_node ihnode;
	struct hlist_node nhnode;
	__u32 type;
	__u32 ID;
	char name[MAX_NAME_LENGTH_INTERNAL];
	__u32 refered;
	__u32 refer;
	unsigned long refer_block[MAX_REFER_NUM];

	__u32 data_len;
	__u32 vsid;

	atomic_t count;
	int valid;

	void *data;
};


struct cfg_req
{
	__u32   size;
	__u32   obj_type;
	__u32   cmd_type;
	__u32   ID;
	__u32   ID2;
	char    name[MAX_NAME_LENGTH];
	__u32   refer;
	__u32   refer_block[MAX_REFER_NUM];
	__u32   vsid;
	__u32   reserve2;
	__u32   data_len;
	unsigned long pad;
	char    data[0];
};

#define OBJ_DATA_ALIGN(x) ((x + 3) & ~3)

struct hls_service{
	__u16		protocol;
	__u16		port;
	__u16		port2;
	char		comment[128];
};

#define ADDRESS_DETAIL_MAX		256


#define ADDRESS_TYPE_HOST		1
#define ADDRESS_TYPE_SUBNET 	2
#define ADDRESS_TYPE_RANGE		3

struct address {
	struct list_head group;
	__u32 obj_type;
	__u32 type;
	char name[MAX_NAME_LENGTH]; /* same as obj->name, auto filled by address callback */	
	__u32 parent; /* ID of address group which was included */
	
	__u32 ip1;
	__u32 ip2;
	__u32 n_total;
	__u32 n_detail;
	void *detail;
	__u32 max_session;
	
	__u8 mac[6];
	__u8 bindmac;
	__u8 qos_share;

	__u32 upload; /* kbitps */
	__u32 download;

	void *qdisc[2];

	__u32 n_addr;
	__u32 addr[0];

/*	__u8 wtype;	// wireless device type, 0:wired, 1:ap, 2:sta 
	__u8 wid;
	__u8 channel;
	__u8 is_rogue;
	__u8 is_internal;
	__u8 peer;
	__u8 action;
	__u8 event;*/
};


struct address_group {
	struct list_head group;
	__u32 obj_type;
	__u32 parent;
	char name[MAX_NAME_LENGTH]; /* same as obj->name, auto filled by address callback */	
	struct list_head child;	
};


struct auth {
	char name[MAX_NAME_LENGTH];
	char passwd[32]; /* store in MD5 */
	char department[64];
	char phone[MAX_NAME_LENGTH];
	char mobile[MAX_NAME_LENGTH];
};


struct if_ether {
	char valid;
	char manage;
	char name[16];
	char bridge[16]; /*  */
	unsigned short speed;
	unsigned char duplex;
	unsigned char autoneg;
	unsigned char mac[6];
	unsigned short mtu;
	char shutdown;
	char ip[32];
};

struct if_ether_obj {
	struct if_ether eth[MAX_INTERFACE_NUM];
};

struct if_bridge {
	__u32 gbw_in, gbw_out;
	char eth_no[2];
	char inner[16], outer[16];
	char name[16];
	char alias[MAX_NAME_LENGTH];
	char ip[32];
};

struct if_bridge_obj {
	struct if_bridge br[MAX_BRIDGE_NUM];
};

struct hls_route {
	__u32 net;
	__u32 mask;
	__u32 gw;
};


#define SCHDL_CYC_WEEK	1
#define SCHDL_CYC_YEAR	2

struct hls_schedule {
	__u16 n_type;
	__u16 week;
	__u32 start, end;
	__u32 except_start, except_end;
	
};


struct qos_class {
	__u32 ratein, rateout;
	__u32 ceilin, ceilout;
	__u32 priority;
	__u32 in_handle, out_handle;
	unsigned int bridge;	
};


struct capp_obj {
	char name[MAX_NAME_LENGTH];
	__u16 udp_ports[32];
	__u16 tcp_ports[32];
	char descr[132];
};


struct policy_obj {
	__u32 src;
	__u32 dst;
	__u32 schedule;
	__u32 qos;
	char app[MAX_NAME_LENGTH];
	int bid;
	int action; /* 1:allow, 2: forbid, 0: qos */
	int enable;
};


struct ntp_config {
	char server[MAX_NAME_LENGTH];
	int autosync;
};

#define HTTP_METHOD_ANY 0
#define HTTP_METHOD_GET 1
#define HTTP_METHOD_POST 2
#define HTTP_ACTION_PERMIT 0
#define HTTP_ACTION_FORBID 1
#define HTTP_ACTION_ALERT 2
#define HTTP_ACTION_REDIRECT 3

#ifdef __KERNEL__
/*#ifndef __NR_hls_config
#define __NR_hls_config (__NR_pwritev + 1)
#endif*/

typedef int conf_func_t(void * obj, void * cb);
extern struct hls_obj_head *HLS_ID2obj(__u32 ID);
extern struct hls_obj_head *RT_ID2obj(__u32 ID);
extern void config_get(struct hls_obj_head *obj);
extern void config_put(struct hls_obj_head *obj);
extern int get_objM_count(int obj_type);
extern int get_objM_count_vs(int obj_type, __u32 vsid);
extern struct hls_objM_list *get_RT_M_list(__u32 type);
extern unsigned int get_RT_M_count(__u32 type);
extern struct hls_objS *get_RT_objS_head(__u32 type);
extern void *get_RT_objS_data(int type);
extern int HLS_register_func(int obj_type, int cmd_type, conf_func_t *pre, conf_func_t *post);
extern int HLS_unregister_func(int obj_type, int cmd_type);
extern void HLS_obj_name_set_local(int type, int mangle);


#endif

#endif
