
#ifndef	__SESSION_API_H__
#define	__SESSION_API_H__

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <net/checksum.h>
#include <linux/in.h>
#include <asm/atomic.h>
#include <asm/bitops.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>

#include <linux/cache.h>

#include <sys/hls_ioctl.h>

#ifndef atomic64_read
typedef struct {
	volatile long long counter;
} atomic64_t;
#define atomic64_read(v)	((v)->counter)
#define atomic_read(v)		((v)->counter)
#define atomic64_add(i, v) ((v)->counter += i)
#define atomic64_set(v, i) ((v)->counter = i)
#endif
#else	/*__KERNEL__*/

#include "net/unp.h"
#include <netinet/in.h>

#endif	/*__KERNEL__*/

#define HLS_ELEM_SZ	( (sizeof(struct hls_session) + (SMP_CACHE_BYTES - 1)) & \
			 ~(SMP_CACHE_BYTES - 1) )

#define	HANDLE_HI_MASK		0xfffffc00
#define	HANDLE_LO_MASK		0x000003ff
#define	HANDLE_HI_SHIFT		10

#define	HLS_NULL_HANDLE			0
#define	HLS_DIR_REQUEST			0
#define	HLS_DIR_RESPONSE			1

#define HLS_PRIVATE_AR	0

#define	HLS_MAX_PRIVATE			1

#ifdef __KERNEL__
struct half_session {
	struct hlist_node hnode;
	__u32 hash;
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8 protocol;
	__u8 status;
	__u8 offset;
	__u8 vsid;

	__u16 app_type;
	__u16 qos_id;

	struct tnode *tnode;

	atomic64_t total_bytes;
	atomic_t bytes;
	atomic_t pkts;
	
	__u32 slowpath;

	__u32 time_netflow;

	__u32 pad[1];
};

struct session_private {
	atomic_t refers;
	void *private;
};

struct hls_session {
	struct half_session client, server;	// 128  32
	struct hls_session *next, *prev;

	__u8 bid;
	__u8 expire_queue;
	__u16 session_age;
	__u16 policy_age;
	__u16 cflags;

	struct hls_session *parent;

	atomic_t flags;
#ifdef __KERNEL__
	spinlock_t lock;
#else
	unsigned int pad;
#endif

	__u32 cache_id;
	atomic_t ref;

	unsigned long expires;
	unsigned long time_open;
	unsigned long time_sync;

	struct node_track *nt;
	struct session_private private[HLS_MAX_PRIVATE];
}
#ifdef __KERNEL__
____cacheline_aligned
#endif
;

struct hls_pkt {
	struct sk_buff *skb;
	struct net_device *indev;
	struct net_device *outdev;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	union {
		struct tcphdr *tcph;
		struct udphdr *udph;
		struct icmphdr *icmph;
		unsigned char *raw;
	} l4h;
	unsigned int len;
	unsigned char *data;
	struct hls_session *ts;
	unsigned char dir;
	unsigned char bid;
	__u8 protocol;
};

struct tnode {
	struct hlist_node hnode;
	spinlock_t lock;
	atomic_t refcnt;
	__u32 ip;
	__u32 brid;
	unsigned long create_time;
	unsigned long last;
	unsigned int age;

	struct hls_stats stats;
	struct rb_root dstats;
	unsigned long ban;
	unsigned char bindmac[6];
	unsigned char mac[6];
	char macbind;
	char name[MAX_NAME_LENGTH];
	char department[MAX_NAME_LENGTH];
};

struct tnode_dstats {
	struct rb_node rb_node;
	__u32 app;
	//__u32 timestamp;
	struct hls_stats stats;
	//__u32 session;
	//__u64 bytes[4];

};
#endif

extern int ts_flag_fast_switch[2];

#define HLS_FLAG_IDLE		0x0001
#define HLS_FLAG_NEVER_EXPIRE	0x0002
/*close udp bcast session after sending packet*/
#define HLS_FLAG_UDP_BCAST	0x0004
#define HLS_FLAG_LOCAL		0x0008
/*HLS changed, shoud inform fast path*/
#define HLS_FLAG_SYNC		0x0010
#define HLS_FLAG_SNAT		0x0020
#define HLS_FLAG_DNAT		0x0040
#define HLS_FLAG_NAT		(HLS_FLAG_SNAT | HLS_FLAG_DNAT)
#define HLS_FLAG_MULTICAST	0x0080
#define	HLS_FLAG_FAST_SWITCH0	0x0100
#define	HLS_FLAG_FAST_SWITCH1	0x0200
#define HLS_FLAG_TRANSPARENT_COMM	0x0400
#define HLS_FLAG_HA		0x0800
#define HLS_FLAG_DONT_HA	0x1000
#define HLS_FLAG_REAL_NEVER_EXPIRE 0x2000
#define HLS_FLAG_BLOCKED	0x4000
#define HLS_FLAG_RST_CLOSE	0x8000

#define HLS_FLAG_NOT_READY 0x10000
#define	HLS_FLAG_FAST_SWITCH 0x20000

#define	HLS_FLAG_CONFIRM 0x80000
#define	HLS_FLAG_CREATE 0x100000
#define HLS_FLAG_REVERSE 	 0x200000

#define HLS_FLAG_UNAUTHED	0x400000

static inline int get_bits_from_flag(unsigned int flag)
{
	if (__builtin_constant_p(flag)) {
		if (flag == (1 << 0))
			return 0;
		if (flag == (1 << 1))
			return 1;
		if (flag == (1 << 2))
			return 2;
		if (flag == (1 << 3))
			return 3;
		if (flag == (1 << 4))
			return 4;
		if (flag == (1 << 5))
			return 5;
		if (flag == (1 << 6))
			return 6;
		if (flag == (1 << 7))
			return 7;
		if (flag == (1 << 8))
			return 8;
		if (flag == (1 << 9))
			return 9;
		if (flag == (1 << 10))
			return 10;
		if (flag == (1 << 11))
			return 11;
		if (flag == (1 << 12))
			return 12;
		if (flag == (1 << 13))
			return 13;
		if (flag == (1 << 14))
			return 14;
		if (flag == (1 << 15))
			return 15;
		if (flag == (1 << 16))
			return 16;
		if (flag == (1 << 17))
			return 17;
		if (flag == (1 << 18))
			return 18;
		if (flag == (1 << 19))
			return 19;
		if (flag == (1 << 20))
			return 20;
		if (flag == (1 << 21))
			return 21;
		if (flag == (1 << 22))
			return 22;
		if (flag == (1 << 23))
			return 23;
		if (flag == (1 << 24))
			return 24;
		if (flag == (1 << 25))
			return 25;
		if (flag == (1 << 26))
			return 26;
		if (flag == (1 << 27))
			return 27;
		if (flag == (1 << 28))
			return 28;
		if (flag == (1 << 29))
			return 29;
		if (flag == (1 << 30))
			return 30;
		if (flag == (1 << 31))
			return 31;
	}

	return 0;
}

#define HLS_FLAG_BIT_POS(flag)  get_bits_from_flag(flag);

#define HLS_FLAG( _ts, flag )	( atomic_read(&(_ts)->flags) & flag )

#define HLS_SET_FLAG( _ts, flag )	do { \
					int bit = HLS_FLAG_BIT_POS( flag ) ; \
					set_bit( bit, (volatile unsigned long *)&(_ts)->flags ) ; \
				} while(0)

#define HLS_CLEAR_FLAG( _ts, flag ) do { \
					int bit = HLS_FLAG_BIT_POS( flag ) ; \
					clear_bit( bit,  (volatile unsigned long *)&(_ts)->flags ) ; \
				} while(0)

/*test_and_set_bit - Set a bit and return its old value */
#define HLS_TEST_AND_SET_FLAG( _ts, flag )	 \
				({ \
					int bit = HLS_FLAG_BIT_POS( flag ) ; \
					test_and_set_bit( bit, (volatile unsigned long *) &(_ts)->flags ) ; \
				})

#define HLS_TEST_AND_CLEAR_FLAG( _ts, flag )	 \
				({ \
					int bit = HLS_FLAG_BIT_POS( HLS_FLAG_##flag ) ; \
					test_and_clear_bit( bit,  (volatile unsigned long *)&(_ts)->flags ) ; \
				})

#define	HLS_ERROR_HANDLE			-1
#define	HLS_ERROR_NOT_CONFIRMED		-2
#define	HLS_ERROR_CONFIRMED		-3
#define	HLS_ERROR_ATTACHED		-4
#define	HLS_ERROR_NOT_ATTACHED		-5
#define	HLS_ERROR_DUPLICATED		-6
#define	HLS_ERROR_NOT_ESTAB		-7
#define	HLS_ERROR_PRIV			-8
#define	HLS_ERROR_VSID			-9
#define	HLS_ERROR_TIMEOUT_VALUE		-10
#define	HLS_ERROR_TIMEOUT_STAT		-11
#define	HLS_ERROR_PRIV_FUN		-12
#define	HLS_ERROR			-255

#define	HLS_TIMEOUT_TRANSFER		0
#define	HLS_TIMEOUT_HANDSHAKE		1
#define	HLS_TIMEOUT_CLOSE		2
#define	HLS_TIMEOUT_UDP			(HLS_TIMEOUT_CLOSE + 1)
#define	HLS_TIMEOUT_OTHER		( HLS_TIMEOUT_UDP + 1 )
#define	HLS_TIMEOUT_NEVER_EXPIRE		( HLS_TIMEOUT_OTHER + 1 )
#define HLS_TIMEOUT_BLOCKD		(HLS_TIMEOUT_NEVER_EXPIRE + 1)
#define	HLS_TIMEOUT_STATS		( HLS_TIMEOUT_BLOCKD + 1 )

#define	HLS_TIMEOUT_HANDSHAKE_DEFAULT	100
#define	HLS_TIMEOUT_HANDSHAKE_MIN		10
#define	HLS_TIMEOUT_HANDSHAKE_MAX		200

#define	HLS_TIMEOUT_TRANSFER_DEFAULT		1800
#define	HLS_TIMEOUT_TRANSFER_MIN		10
#define	HLS_TIMEOUT_TRANSFER_MAX		7200

#define	HLS_TIMEOUT_CLOSE_DEFAULT		20
#define	HLS_TIMEOUT_CLOSE_MIN			3
#define	HLS_TIMEOUT_CLOSE_MAX			800

#define	HLS_TIMEOUT_UDP_DEFAULT		120
#define	HLS_TIMEOUT_UDP_MIN			10
#define	HLS_TIMEOUT_UDP_MAX			7200

#define	HLS_TIMEOUT_OTHER_DEFAULT		20
#define	HLS_TIMEOUT_OTHER_MIN			10
#define	HLS_TIMEOUT_OTHER_MAX			7200

#define	HLS_TIMEOUT_SYN_PROXY_DEFAULT	2
#define	HLS_TIMEOUT_SYN_PROXY_MIN		1
#define	HLS_TIMEOUT_SYN_PROXY_MAX		20

#define	HLS_NEVER_EXPIRE_DEFAULT		20
#define	HLS_NEVER_EXPIRE_MIN			5
#define	HLS_NEVER_EXPIRE_MAX			90

#define	HLS_SYN_PROXY_QUOTA_DEFAULT		2000
#define	HLS_SYN_PROXY_QUOTA_MIN		10
#define	HLS_SYN_PROXY_QUOTA_MAX		200000

#define	HLS_SYN_PROXY_BURST_DEFAULT		5000
#define	HLS_SYN_PROXY_BURST_MIN		10
#define	HLS_SYN_PROXY_BURST_MAX		500000

#define	HLS_STAT_IDLE			0
#define	HLS_STAT_SYN_RCVD		1
#define	HLS_STAT_SACK_WAIT		2
#define	HLS_STAT_ESTAB			3
#define	HLS_STAT_CLOSING			4
#define	HLS_STAT_CLOSED			5

/*reject in post-sesion hook, only used by session-monitor*/
#define	HLS_STAT_REJECT			6

#define	HLS_MAX_SP_RETRIES		3
#define	HLS_SP_STAT_SYN_RCVD		100
#define	HLS_SP_STAT_SYN_SND		101

struct filter_rule {
	__u32 bitmap;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
};

#define FILTER_SADDR_BIT	0x1
#define FILTER_DADDR_BIT	0x2
#define FILTER_PROTO_BIT	0x4
#define FILTER_SPORT_BIT	0x8
#define FILTER_DPORT_BIT	0x10
#define FILTER_SMAC_BIT 	0x20
#define FILTER_DMAC_BIT 	0x40
#define FILTER_ALL_BIT 0x80000000

struct ts_addr_info {
	__u8 protocol;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct ts_statistic {
	__u32 server_pkts;
	__u32 client_pkts;
	__u64 server_bytes;
	__u64 client_bytes;
};

#define HLS_DEFAULT_PROTOCOL	256

struct session_cmd {
	short type;
	__u8 vsid;
	__u8 protocol;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 number;
};

#ifdef __KERNEL__

extern int HLS_init(void);
extern void HLS_exit(void);
extern int HLS_recv_pkt(struct hls_pkt *pkt, int *new, int *close_after_send);
extern struct hls_session *HLS_find(__u8 protocol, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, int get);
extern int HLS_delete(struct hls_session *ts);
extern struct hls_session *HLS_create_ha(__u8 protocol, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport);
extern int HLS_confirm(struct hls_session *ts);
extern int HLS_is_confirmed(struct hls_session *ts);
extern void HLS_flush(void);
extern int HLS_fast_path(struct hls_session *ts);
extern int HLS_in_cache(struct hls_session *ts);
extern int HLS_set_sync(struct hls_session *ts);
extern int HLS_get_addr_info(struct hls_session *ts, int dir, struct ts_addr_info *info);
extern int __HLS_get_addr_info(struct hls_session *ts, int dir, struct ts_addr_info *info);
extern int HLS_get_handshake(struct hls_session *ts, int *stat);
extern int HLS_get_total(__u32 * total);
extern int HLS_get_proto_statistic(__u8 protocol, __u32 * t, __u32 * p, __u32 * h, __u32 * f);
extern int HLS_set_timeout(int protocol, int state, __u32 value);
extern int HLS_get_timeout(int protocol, int state, __u32 * value);
extern int HLS_set_never_expire(struct hls_session *ts, int enable);
extern int HLS_get_flags(struct hls_session *ts, int *flags);
extern int HLS_can_ha(struct hls_session *ts);
extern int HLS_set_dont_ha(struct hls_session *ts);
extern int HLS_set_transparent_comm(struct hls_session *ts, int on);
extern int HLS_set_qos_id(struct hls_session *ts, int dir, __u16 qos_id);
extern int HLS_get_qos_id(struct hls_session *ts, int dir, __u16 * qos_id);
extern int HLS_set_log(struct hls_session *ts, int on);
extern int HLS_set_snat(struct hls_session *ts, int on);
extern int HLS_set_dnat(struct hls_session *ts, int on);
extern int HLS_get_app_type(struct hls_session *ts, __u16 * type);
extern int HLS_set_app_type(struct hls_session *ts, __u16 type);
extern int HLS_set_tnode(struct hls_session *ts, struct tnode *node);
extern int HLS_set_node_track(struct hls_session *ts, struct node_track *nt);

extern int HLS_set_fw_expire(struct hls_session *ts, __u32 data);
extern int HLS_get_fw_expire(struct hls_session *ts, __u32 * data);
extern int HLS_set_parent(struct hls_session *ts, struct hls_session *parent);
extern int HLS_get_parent(struct hls_session *ts, struct hls_session *parent);
extern __u32 HLS_register_priv_fun(void *f);
extern int HLS_unregister_priv_fun(__u32 id);
extern int HLS_attach_private(struct hls_session *ts, __u32 id, void *data);
extern int HLS_detach_private(struct hls_session *ts, __u32 id);
extern int HLS_get_private(struct hls_session *ts, __u32 id, void **data);
extern void HLS_put_private(struct hls_session *ts, __u32 id);

extern int hls_session_on;
extern int hls_skip_checksum;

/*
*negative means HLS_HANDLE invalid,
*1 means suitable for ha.
*/
extern int HLS_set_slowpath(struct hls_session *ts, __u32 id);
extern int HLS_get_slowpath(struct hls_session *ts, __u32 id);
extern void HLS_clear_slowpath(struct hls_session *ts, __u32 id);

void HLS_ha_session_flush(__u8 vsid, unsigned long ip);
extern void (*ha_session_sync_flush) (__u8 vsid, unsigned long ip);
extern unsigned long (*ha_active_state_clock) (void);

#define HLS_SLOWPATH_HTTP	4
#define HLS_SLOWPATH_DPI	9
#define HLS_SLOWPATH_LOCAL	25
#define HLS_SLOWPATH_ARP	26
/*route has two direction*/
#define HLS_SLOWPATH_ROUTE0	27
#define HLS_SLOWPATH_ROUTE1	28
#define HLS_SLOWPATH_DHCP	29

#define HLS_SLOWPATH_IDS	30

#ifndef MONITOR_NUM
#define MONITOR_NUM 16
#endif

#define SE_PRI_MIN          0

#define INADDR_UNSPEC_GROUP   	0xe0000000U	/* 224.0.0.0   */
#define INADDR_ALLHOSHLS_GROUP 	0xe0000001U	/* 224.0.0.1   */
#define INADDR_ALLRTRS_GROUP    0xe0000002U	/* 224.0.0.2 */
#define INADDR_MAX_LOCAL_GROUP  0xe00000ffU	/* 224.0.0.255 */
/* Some random defines to make it easier in the kernel.. */
#define LOOPBACK(x)	(((x) & htonl(0xff000000)) == htonl(0x7f000000))
#define BROADCAST(x)	(((x) & htonl(0xffffffff)) == htonl(0xffffffff))
#define MULTICAST(x)	(((x) & htonl(0xf0000000)) == htonl(0xe0000000))
#define BADCLASS(x)	(((x) & htonl(0xf0000000)) == htonl(0xf0000000))
#define ZERONET(x)	(((x) & htonl(0xff000000)) == htonl(0x00000000))
#define LOCAL_MCAST(x)	(((x) & htonl(0xFFFFFF00)) == htonl(0xE0000000))

extern atomic_t ts_hash_num;

void session_check_close(struct hls_session *ts);

#define HLS_IP_PROTO_VALID	0x01

extern unsigned Tnode_max_num;
extern atomic_t HLS_total_num, HLS_nat_num, HLS_nat_fail, HLS_num[256], HLS_never_expire_num,
    HLS_total_confirm, HLS_pool_num;
extern atomic_t HLS_not_ready_num;
extern atomic_t tnode_cnt;
extern int ts_total_entries;
extern __u32 HLS_cps;
extern __u32 HLS_nat_original, HLS_nat_hash, HLS_nat_random;
extern void *ts_area;
extern __u16 *ts_age;
extern int hls_icmp_redirect, hls_tcp_reset;

enum {
	SESSION_ACTIVE,
};
int register_session_notifier(struct notifier_block *nb);
int unregister_session_notifier(struct notifier_block *nb);

extern void HLS_inc_policy_age(void);
extern __u32 HLS_policy_age;
static inline int HLS_policy_changed(struct hls_session *ts)
{
	if (ts->policy_age != HLS_policy_age)
		return 1;

	return 0;
}

extern void HLS_update_policy_age(struct hls_session *ts);
extern int HLS_get_policy_age(struct hls_session *ts);

/*use server slowpath as extra flags*/
#define HLS_XFLAG_POLICY_ROUTE0	0x01
#define HLS_XFLAG_POLICY_ROUTE1	0x02

#endif

#ifndef LELEM
#define LEMPTY		0UL
#define LELEM(opt)	(1UL << (opt))
#endif

#define DSESSION_RCV      LELEM(12)
#define DSESSION_LOCK      LELEM(13)
#define DSESSION_EXPIRE      LELEM(14)
#define DSESSION_REF      LELEM(15)
#define DSESSION      LELEM(16)
#define DSESSION_TCP      LELEM(17)
#define DSESSION_PRIVATE LELEM(18)
#define DSESSION_FASTPATH LELEM(19)
#define DSESSION_NAT LELEM(20)
#define DSESSION_SLOWPATH LELEM(21)

#define DVERBOSE	LELEM(31)

extern unsigned long debug_options;

#if 1
#define HLS_PRINTK(flag, format, args...) \
	((debug_options& (flag)) ? printk(format,## args) : 0)
#else
#define HLS_PRINTK(flag, format, args...)
#endif

/***************************  APP API **************************************/

extern void APP_stat_inc_session(__u8 brid, __u16 aid);
extern void APP_stat_dec_session(__u8 brid, __u16 aid);
extern void APP_stat_bytes(__u8 brid, __u16 aid, int bytes_up, int bytes_down);

/*************************** end of APP API *******************************/

#endif
