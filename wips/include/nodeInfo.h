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
	void* module;//eventLibLinkInfo_t*
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

typedef struct radioInfo_s
{	
	int signal;
	int noise;
	int freq_band;
	__u32 channel;
	__u32 rates;

}radioInfo_t;


typedef struct w_node
{
	__u8 mac[ETH_ALEN];
	__u8 initFlag;
	time_t upTime;
	time_t lastTime;
	radioInfo_t radioInfo;
	wNodeMem_t memInfo;
	void* memPayload2LibEvent;
	int memPayload2LibEventLen;
	proberInfo_t proberInfo;

}wNode_t;






#endif
