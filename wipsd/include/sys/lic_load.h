#ifndef __LIC_LOAD_H__
#define __LIC_LOAD_H__

#include <linux/types.h>

#define WORD_LEN 128
#define TIME_LEN 32

struct __lic_info{
	char  	serialno[WORD_LEN];
	char	lic_type[WORD_LEN];

	char	expire_time[WORD_LEN];
	__u32	max_sessions_num;
	__u32	max_ips_num;
	__u32	lic_invalid;
	__u32	max_ap;
	/*reserve*/
	__u32	reserver[1020];
};

struct __lic_info lic_info;
extern struct __lic_info lic_info;
#endif
