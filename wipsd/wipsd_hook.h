//  Wipsd_hook.h
#ifndef _H_WIPSD_HOOK
#define _H_WIPSD_HOOK

typedef struct bwlist_node
{
	struct bwlist_node * next;
	void *data;
	__u32 type;
#define BLACK_SSID	0
#define WHITE_SSID	1
#define BLACK_TIME_DOMAIN	2
#define WHITE_TIME_DOMAIN	3
}bwlist_node;

int average_event_count(int * count, int * cum, int * average, 
	int data, int * interval, int inter_max);

int read_aplist_config(void* data, int n_columns, char** column_values, 
	char** column_names);

int read_stalist_config(void* data, int n_columns, char** column_values, 
	char** column_names);

int read_iplist_config(void* data, int n_columns, char** column_values, 
	char** column_names);

int read_ap_essid(void* data, int n_columns, char** column_values, 
	char** column_names);

int update_nodeinfo_list(void);

int check_adhoc_ap_ssid(struct w_node * node_frame, int initch);

int check_ap_essid_seting(struct w_node * node_frame, int initch);

int check_apnumber_eachchannel(__u16 channel, int initch);

int check_default_ssid(char * ssid);

void check_channel_blacklist(struct w_node * latest,struct w_node * exist,
			int initlist, int forbidchannel, int enablechannel);
void init_channel_blacklist(void);

void check_bitrate_blacklist(struct w_node * latest,struct w_node * exist,
			int initlist, int forbidrate, int enablerate);

void check_auth_device(struct w_node * latest,struct w_node * exist);

void check_address(struct w_node * latest,struct w_node * exist);

void check_lsatpkgtype(struct w_node * latest,struct w_node * exist, int pkgtype);

void check_bitrate(struct w_node * latest,struct w_node * exist);

void check_braodcast_storm(struct w_node * latest,struct w_node * exist);

void check_signal(struct w_node * latest,struct w_node * exist);

void check_freq_interference(struct w_node *sta_val);

void check_freq_suppression(struct w_node *sta_val);

void check_freq_err(struct w_node *sta_val);

void print_event_info(int event_number, struct w_node *sta_val);

int working_time_check(void);

int check_object_essid(char * wnet,struct w_node * exist);

int check_unworktime_essid_from_wnet(char * wnet);

int check_internal_essid_from_wnet(char * wnet);

int check_unauth_essid(struct w_node * exist);

int init_essid_hash_table(void);

int check_object_vendor(char * object,char * vendor);

int init_ctime_hash_table(void);

int get_object_ctime(void);

int check_object_ctime(char * ctime);

int blocked_bssid_with_sta(struct w_node * exist);

void free_blocked_bssid(struct w_node * exist);

int channel2ieee(__u8 freq_band, __u32 channel);

void check_wireless_object(struct w_node * latest,struct w_node * exist);

#endif
