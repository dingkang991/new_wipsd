#ifndef __NODE_H__
#define __NODE_H__
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include "io_support.h"
//#include "eventInfo.h"
#include "common.h"


typedef struct wNodeMemMap_s{
	//eventLibLinkInfo_t *module;
	void* module;
	int memOffset;
	int memLen;
}wNodeMemMap_t;

typedef struct wNodeMem_s
{
	int memLen;
	void* memStart;
	wNodeMemMap_t *memMap;
}wNodeMem_t;



typedef struct proberInfo_s{
	struct uloop_fd *fd;
	struct sockaddr_in addr;
	__u8 proberMac[ETH_ALEN]; //增加探针源mac地址
}proberInfo_t;
	

typedef struct w_node
{
	__u8 mac[ETH_ALEN];//MAC
	__u8 peer_mac[ETH_ALEN];
	char vendor[128];
	char sec_type[48];//WPA/RSN parameters
	char 
	char ssid[SSID_BUFSIZE_D];//ssid
	
//	time_t up_time;
//	time_t last_time;

	int signal;
	int noise;
	int freq_band;
	__u32 channel;
	__u32 rates;

	__u16 reason_code;

	__u8 bssid[ETH_ALEN];//MAC
	__u8 dstmac[ETH_ALEN];//MAC
	__u8 lan_mac[ETH_ALEN];//MAC
	__u8 essid_id[ETH_ALEN];//MAC
	__u8 ssid_len;//ssid_len_FN
	wNodeMem_t memInfo;
	void* memPayload2LibEvent;
	int memPayload2LibEventLen;
	
	proberInfo_t proberInfo;

}wNode_t;



#endif
