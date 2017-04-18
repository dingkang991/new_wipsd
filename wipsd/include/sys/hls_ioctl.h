#ifndef __HLS_STATS_H__
#define __HLS_STATS_H__



#ifndef MAX_NAME_LENGTH
#define MAX_NAME_LENGTH 32
#endif

struct hls_req {
	__u32 id;		/* 要获取对象的id */
	char name[MAX_NAME_LENGTH];	/* 要获取对象的名称，id非0时，以id为准 */
	int cmd;
	int value;		/*设定值 */
	char *base;		/* 用户空间的缓冲区 */
	int len;		/* 缓冲区长度的地址 */
	int *rt_len;		/* 系统会将实际的长度回填到这里 */
};


struct hls_stats {
	__u64 bytes[4];
	__u32 throughout[2];
	__u32 calc_time;
#ifdef __KERNEL__	
	atomic_t sessions;
#else
	__u32 sessions;
#endif
	__u32 pkts[4];
};


struct tn_elem {
	__u64 bytes[2];		/* 0 流出，1 流入 */
	__u32 throughout[2];
	__u32 total_session;
	__u32 app_session;
	__u32 baned;
	__u32 ip;
	__u32 jiffies_diff;
	unsigned char mac[6];
	unsigned char pad[2];
	char name[MAX_NAME_LENGTH];
	char department[MAX_NAME_LENGTH];
};


struct ds_elem {
	__u64 bytes[2];		/* 0 流出，1 流入 */
	__u32 throughout[2];
	__u32 session;
	__u32 app;
	__u32 jiffies_diff;
	char name[MAX_NAME_LENGTH];
};


struct app_elem {
	__u64 bytes[2];		/* 0 流出，1 流入 */
	__u32 speed[2];
	__u32 session;
	__u16 aid;
	char name[MAX_NAME_LENGTH];
	char name_en[MAX_NAME_LENGTH];
};

struct app_elems {
	__u64 bytes[2];		/* 0 流出，1 流入 */
	__u32 speed[2];
	__u32 session;
	__u16 aid;
	char name[MAX_NAME_LENGTH];
	char name_en[MAX_NAME_LENGTH];
};

struct ep_elem {
	__u64 bytes[2];		/* 0 流出，1 流入 */
	__u32 speed[2];
	__u32 session;
	__u32 ip;
	unsigned long start_time;
};


struct session_elem {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;

	__u32 pkts[2];
	__u64 bytes[2];
	__u32 time;
	__u8 protocol;

	char app[MAX_NAME_LENGTH];

	char pad[3];
};

struct wips_elem {
	__u32 total_session;
	__u32 baned;
	__u32 ip;
	unsigned long create_time;
	unsigned long last;
	unsigned long age;
	unsigned long macbind;
	unsigned char bindmac[6];
	unsigned char mac[6];
	char name[MAX_NAME_LENGTH];
	char department[MAX_NAME_LENGTH];
};

//added by cp
#define MAX_ADDR_GRP_NUM	32
struct dep_elem {
	char department[MAX_NAME_LENGTH];
	__u64 bytes[2];		/* 0 流出，1 流入 */
	__u32 dep_id;
	__u32 throughout[2];
	__u32 total_session;
	__u32 app_session;
	__u32 ip_num;
};

#define HLS_CMD_GSTATS _IO(0x11, 0)
#define HLS_CMD_RULE _IO(0x11, 1)
#define HLS_CMD_OPERATE _IO(0x11, 2)


#define APP_SAVE_INTVAL 600	// 10分钟保存一次
#define APP_SAVE_SIZE (6*24*31)	// 保存一个月

struct save_head {
	int index;
	time_t timestamp;
};

struct save_elem {
	__u32 speed[2];
	__u32 session;
};

struct save_elem_brs {
	struct save_elem elem;
};


struct save_elem_session {
	__u32 sessions;
	__u32 cps;
	__u32 tnodes;
};

struct save_elem_session_brs {
	struct save_elem_session elem;
};

struct save_elem_dev {
	__u32 throughout[2];
};

enum {
	STATS_TYPE_HNODE,
	STATS_TYPE_APP,
	STATS_TYPE_APPGRP,
	STATS_TYPE_TNODE_OF_APP,
	STATS_TYPE_TNODE_DETAIL,
	STATS_TYPE_TNODE_CURRENT,
	STATS_TYPE_TNODE_SHARE,
	STATS_TYPE_TNODE_OF_DEP,
	STATS_TYPE_TNODE_OF_DEP_TOTAL,
	STATS_TYPE_TNODE_OF_DEP_APP,
	STATS_TYPE_TNODE_OF_DEP_IP,
	STATS_TYPE_DEV_CURRENT,
	STATS_TYPE_STATS_RING,
	STATS_TYPE_APP_NAME,
	STATS_TYPE_IP_SESSION,
	STATS_TYPE_APPGRP_CURRENT,
	STATS_TYPE_IPS_DEC,
	STATS_TYPE_IPS_ATTACK,
	STATS_TYPE_FW,
	STATS_TYPE_WIPS_MAC,
};


enum {
	OPERATE_TYPE_BAN_TNODE,
	OPERATE_TYPE_AUTH,
};
#endif


