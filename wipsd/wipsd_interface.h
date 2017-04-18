#ifndef __WIPS_INTERFACE_H__
#define __WIPS_INTERFACE_H__

#define WIPSD_SOCKET_PORT 13524

struct wipsd_interface
{
	struct list_head list;
	struct interface *itf;

	struct fdu rcv;
	//struct fdu send;

	u32 ip;
};

struct wipsd_interface_hdr
{
	struct list_head list;

	u32 cnt;
};

struct wipsd_ipc_data
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
}__attribute__((packed));

enum prober_ipc_cmd
{
	WIPSD_IPC_CMD,

	WIPSD_ADD_BLOCK_INFO,
	WIPSD_DEL_BLOCK_INFO,
};

int wipsd_init_timer(void);
void *wipsd_capture(void *arg);
void wipsd_block_by_lan(int pid, struct w_node *node, int cmd);
void wipsd_block_by_wireless(struct wipsd_ipc_data *data, struct w_node *node, int cmd);
struct wipsd_interface *wipsd_if_create(struct interface *itf);
int wipsd_if_start(struct wipsd_interface *wipsd_if);
int wipsd_if_destroy(struct wipsd_interface *wipsd_if);
int send_ap_info(struct w_node *node,char* func_name);


#endif

