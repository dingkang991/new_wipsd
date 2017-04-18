#ifndef _H_BUILD_TREE
#define _H_BUILD_TREE
#define SSID_SEQUENCE_HEAD "\x53\x53\x49\x44\x5f"	//\x53\x53\x49\x44\x5f\x00 is hidingSsid node

enum {
	CHANNEL_ROOT_INIT,
		
	CHANNEL_AP_ROOT_ADD,
	CHANNEL_AP_ROOT_DEL,
	ESSID_AP_ROOT_ADD,
	ESSID_AP_ROOT_DEL,
	
	CHANNEL_STA_ROOT_ADD,
	CHANNEL_STA_ROOT_DEL,
	
	GET_CHANNEL_STA_ROOT,
	GET_CHANNEL_AP_ROOT,
	GET_ESSID_AP_ROOT_BY_NAME,
	GET_ESSID_AP_ROOT_BY_ID,
	GET_ESSID_ID_NUMBER
};

struct w_node * channel_root(struct w_node *tmp, int tasktype, int channel);
struct w_node * essid_root(struct w_node *tmp, int tasktype);
//ssid_name_id * get_ssid_name_id_array(__u8 essid_number);

int tree_ap_ssid_change(struct w_node *node);
int tree_ap_channel_change(struct w_node *node);
int tree_sta_bssid_change(struct w_node *node);
int tree_sta_channel_change(struct w_node *node);

int tree_get_essid_name_id(ListBuf * treebuf);
int tree_get_by_essid_id(ListBuf * treebuf, struct w_node *node);
int tree_get_by_a_essid(ListBuf * treebuf, struct w_node *node);
int block_sta_with_a_essid(struct w_node *node);
int tree_get_all_essid(ListBuf * treebuf);
int tree_get_by_channel(ListBuf * treebuf, struct w_node *node);
int tree_get_all_channel(ListBuf * treebuf);
int tree_get_islandsta_by_channel(ListBuf * treebuf, struct w_node *node);
int tree_get_islandsta_all_channel(ListBuf * treebuf);

#endif
