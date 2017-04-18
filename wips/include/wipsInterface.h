#ifndef __WIPS_INTERFACE_H__
#define __WIPS_INTERFACE_H__
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <asm/types.h>
#include "ustream.h"
#include "uloop.h"
#include "usock.h"
#include "eventInfo.h"

#define WIPSD_SOCKET_PORT 13524
#define WIPSD_SOCKET_PORT_STR "13524"
#define WIPS_PKT_MAX_LEN	2048


struct fdu {

	
	int fd;
	
	void (*read_handler)(struct fdu *, int, void *);
	void (*write_handler)(struct fdu *, int, void *);
	
	void *read_arg;
	void *write_arg;
};

typedef struct wipsInterface_s
{
	struct list_head list;
	char ip[32];
	char port[8];
	int fd;
	struct uloop_fd uloopFd;
}wipsInterface_t;


typedef struct wipsIpcData
{
	unsigned char cmd;
	
	unsigned char channel;
	unsigned char freq_band;
	unsigned char block_method; //bit0:deauth, bit1:arp, ...
	
	unsigned char mac[6];
	unsigned char bssid[6];
	unsigned char wgate_mac[6];	
	
	unsigned int ipv4;
	unsigned int wgate_ipv4;
}__attribute__((packed))wipsIpcData_t;

enum prober_ipc_cmd
{
	WIPSD_IPC_CMD,

	WIPSD_ADD_BLOCK_INFO,
	WIPSD_DEL_BLOCK_INFO,
};
extern wipsInterface_t* initWipsInterface(wipsInterface_t* wipsInterface);
extern int wipsInitSocket(wipsInterface_t *wipsIf);
extern void wipsd_handle_packet(struct uloop_fd *fd, unsigned int events);
extern void wipsd_handle_wlansniffrm(__u8 *buf, int len,core2EventLib_t* core2EventLib);
extern wipsInterface_t* setWipsInterface(wipsInterface_t* wipsInterface);

#endif


