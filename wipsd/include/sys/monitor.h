
#ifndef _HOS_MONITOR_GLOB_H_
#define _HOS_MONITOR_GLOB_H_


/* proc file */

#define HLS_MONITOR_PROC		"/proc/hls/monitor/proc"
#define HLS_MONITOR_MEM		"/proc/hls/monitor/mem"
#define HLS_MONITOR_IF			"/proc/hls/monitor/if"
#define HLS_MONITOR_CPU		"/proc/hls/monitor/cpu"
#define HLS_MONITOR_PROC_IOC	"/proc/hls/monitor/ctrl"
#define HLS_MONITOR_SESSION     "/proc/hls/monitor/session"

/* config file */
#define MONITOR_CONF_DIR	"/produce"
#define HLS_RUN_DIR		"/usr/hls/etc/hls.run"
#define MONITOR_TMP_CONF	"/tmp/monitor_tmp"

/* main -- standby */
#define MAIN	1
#define STANDBY	2

/* ioctl command */
#define MONITOR_IOC_MAGIC		'x'
#define MONITOR_IOC_IDLE		_IO(MONITOR_IOC_MAGIC,   0)
#define MONITOR_IOC_RECONF	 	_IO(MONITOR_IOC_MAGIC,   1)



extern int errno;



#define MAX_HLSBUFF_LENGTH  (1024*128)
#define MAX_BUFFER_LENGTH_HLS 4096
#define PROC_LEN 20


#define PROC_STATUS_EXITED	0
#define PROC_STATUS_ALIVE	1
#define PROC_STATUS_ZOMBIE	2
#define HLSBUFF_LEN  ((size_t)(1024*50))


/* session numbers */
#define IPPRO_TCP 0x001
#define IPPRO_UDP 0x002
#define IPPRO_ICMP 0x003


/* netlink */
struct hls_netlink_info {
	int	speed;		/* The forced speed, 10Mb, 100Mb, gigabit */
	int	duplex;		/* Duplex, half or full */
	int	autoneg;	/* Enable or disable autonegotiation */
	__u8	link;
        int     ptype;           /* Tx or T */    
};

#define CPU_INFO_SAVE_NUM 		5

struct proc_info{
	char name[MAX_NAME_LENGTH+1];
	int type;
	pid_t pid;
	unsigned long utime, stime;
	unsigned long last_utime[CPU_INFO_SAVE_NUM];
	unsigned long last_stime[CPU_INFO_SAVE_NUM];
	unsigned long cpu;
	unsigned long mem;
	int flag;
};


/* end of global difinitions */



/* kernel */
#ifdef __KERNEL__


/* global definitions */
#define PROC_SCAN_FREQ	(HZ*5)	/* 5 seconds */


#define HLS_MONITOR_MEM_OVERLOAD	3
#define HLS_MONITOR_CPU_OVERLOAD	95


#define RPT_TYPE_ALL	 0x0001
#define RPT_TYPE_PROC	 0x0005
#define RPT_TYPE_CPU	 0x0002
#define RPT_TYPE_MEM	 0x0003
#define RPT_TYPE_NETIF	 0x0004
#define RPT_TYPE_SESSION 0x0006
	

/* note: these variables are to be exported */
extern int encrypt_card_status;


#define LEFT(x)  (((unsigned)(x)) / 10)
#define RIGHT(x) (((unsigned)(x)) % 10)


#define MAX_CPU_NUM NR_CPUS
#define CPU_SCAN_FREQ (5*HZ)
#define CPU_SAVE_NUM 6	

struct hls_cpu_info {
	unsigned int user;
	unsigned int system;
	unsigned int nice;
	unsigned int total;
	unsigned int idle;
	unsigned int softirq;
	unsigned int irq;
	unsigned int iowait;
	unsigned int steal;
	unsigned int guest;
};


struct hls_mem_info {
	int mem_total;
	int mem_free;
	unsigned int load;
        int mem_buff;
	int mem_cache;
};


struct hls_sys_info{
	struct hls_cpu_info cpu_load[MAX_CPU_NUM];
	struct hls_mem_info mem_load;
	int nr_procs;
};


extern struct hls_sys_info sys_val;


struct proc_list{
	struct proc_info info;
	int status;
	struct proc_list *next;
};


struct proc_watch_info{
	char name[MAX_NAME_LENGTH+1];
	char cpu[PROC_LEN];
	struct proc_watch_info *next;
};


struct hls_watch_info{
	int mem_total;
	int mem_free;
        char memload[PROC_LEN];
	struct proc_watch_info proc_watch;
	unsigned int session_total;
	unsigned int ip_total;
	unsigned int ip_perm;
	unsigned int ip_conn;
	unsigned int ip_disconn;
	unsigned int udp_total;
	unsigned int udp_perm;
	unsigned int udp_conn;
	unsigned int udp_disconn;
	unsigned int icmp_total;
	unsigned int icmp_perm;
	unsigned int icmp_conn;
	unsigned int icmp_disconn;
};
extern struct hls_watch_info hls_watch;



#define NETIF_LINKED	0x0001
#define NETIF_UP	0x0001

int monitor_proc_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);
int monitor_proc_read_cpu(char *page, char **start, off_t off, int count, int *eof, void *data);
int monitor_proc_read_mem(char *page, char **start, off_t off, int count, int *eof, void *data);
int monitor_proc_read_if(char *page, char **start, off_t off, int count, int *eof, void *data);
int monitor_proc_read_session(char *page, char **start, off_t off, int count, int *eof, void *data);
int proc_monitor_ioctl (struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
int get_proc_info(struct proc_info *val);
const char * get_task_state(long tsk_state);
int get_status(int flag);
int monitor_read_config(char *path);


int monitor_init(void);
void monitor_fini(void);

int dump_cpu(char *buf);


#endif  /* __KERNEL__*/
#endif	/* _HLS_MONITOR_GLOB_H_ */


