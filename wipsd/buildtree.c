#include <zebra.h>
#include "zthread_support.h"
#include "if_support.h"
#include "fs_support.h"
#include "io_support.h"
#include "getopt.h"
#include "daemon.h"
#include "mac.h"
#include "zclient.h"
#include "vty.h"
#include "../vtysh/vtysh.h"
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include <linux/in.h>
#include "obstack.h"
#include "hash.h"
#include "ieee80211.h"
#include "sqlite3.h"

#include "wipsd_wnode.h"
#include "hash.h"
#include "buildtree.h"
extern struct hash_control *wlist_hash_table;

#define CHANNEL_NUMBER 27
struct w_node * channel_root(struct w_node *tmp, int tasktype, int channel)
#if 0
{
	static struct w_node channel_ap_root[CHANNEL_NUMBER];
	static struct w_node channel_sta_root[CHANNEL_NUMBER];
	int channel_id;

	channel_id = channel;
	switch(channel_id){
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
			break;
		case 36:
			channel_id = 15;
			break;
		case 40:
			channel_id = 16;
			break;
		case 44:
			channel_id = 17;
			break;
		case 48:
			channel_id = 18;
			break;
		case 52:
			channel_id = 19;
			break;
		case 56:
			channel_id = 20;
			break;
		case 60:
			channel_id = 21;
			break;
		case 64:
			channel_id = 22;
			break;
		case 149:
			channel_id = 23;
			break;
		case 153:
			channel_id = 24;
			break;
		case 157:
			channel_id = 25;
			break;
		case 161:
			channel_id = 26;
			break;
		case 165:
			channel_id = 27;
			break;
		default:
			return NULL;
	}
	channel_id -- ;

	switch(tasktype){
		case CHANNEL_ROOT_INIT:
			memset(channel_ap_root, 0, sizeof(channel_ap_root));
			memset(channel_sta_root, 0, sizeof(channel_sta_root));
			break;
		case CHANNEL_AP_ROOT_ADD:
			if(!tmp) return NULL;
			channel_ap_root[channel_id].child_num ++;
			channel_ap_root[channel_id].channel = channel;
			tmp->pap = channel_ap_root[channel_id].pap;
			tmp->lastap = tmp->laststa = &channel_ap_root[channel_id];
			channel_ap_root[channel_id].pap = tmp;
			if(tmp->pap){
				struct w_node *old_next = tmp->pap;
				old_next->lastap = tmp;
			}
			break;
		case CHANNEL_STA_ROOT_ADD:
			if(!tmp || !(tmp->node_type & 2)){
				return NULL;
			}else{
				w_node_list * p_tmp = NULL;
				p_tmp = (w_node_list * )hash_find(wlist_hash_table, 
					(const char *)tmp->bssid, 6);
				if(p_tmp && (p_tmp->b_frame.node_type &1)){
					p_tmp->b_frame.sta_num++;
					tmp->psta= p_tmp->b_frame.psta;
					tmp->laststa = tmp->lastap = &p_tmp->b_frame;
					p_tmp->b_frame.psta = tmp;
					if(tmp->psta){
						struct w_node *old_next = tmp->psta;
						old_next->laststa = tmp;
					}
				}else{
					channel_sta_root[channel_id].child_num ++;
					channel_sta_root[channel_id].channel = channel;
					tmp->psta= channel_sta_root[channel_id].psta;
					tmp->laststa = tmp->lastap = &channel_sta_root[channel_id];
					channel_sta_root[channel_id].psta = tmp;
					if(tmp->psta){
						struct w_node *old_next = tmp->psta;
						old_next->laststa = tmp;
					}
				}
			}
			break;
		case GET_CHANNEL_AP_ROOT:
			return &channel_ap_root[channel_id];
			break;
		case GET_CHANNEL_STA_ROOT:
			return &channel_sta_root[channel_id];
			break;
		case CHANNEL_AP_ROOT_DEL:
			if(!tmp){
				return NULL;
			}else{
				struct w_node *old_next = tmp->pap;
				struct w_node *old_last = tmp->lastap;
				if(old_last){
					channel_ap_root[channel_id].child_num --;
					old_last->pap = old_next;
				}
				if(old_next) old_next->lastap = old_last;
			}
			break;
		case CHANNEL_STA_ROOT_DEL:
			if(!tmp || !(tmp->node_type & 6)){
				return NULL;
			}else{
				w_node_list * p_tmp = NULL;
				p_tmp = (w_node_list * )hash_find(wlist_hash_table, 
					(const char *)tmp->bssid, 6);
				if(p_tmp ){
					struct w_node *old_next = tmp->psta;
					struct w_node *old_last = tmp->laststa;
					if(old_last){
						p_tmp->b_frame.sta_num --;
						old_last->psta = old_next;
					}
					if(old_next) old_next->laststa = old_last;
				}else{
					struct w_node *old_next = tmp->psta;
					struct w_node *old_last = tmp->laststa;
					if(old_last){
						channel_sta_root[channel_id].child_num --;
						old_last->psta = old_next;
					}
					if(old_next) old_next->laststa = old_last;
				}
			}
			break;
		default :
			return NULL;
	}
	return NULL;
}
#else
{
return NULL;
}
#endif
struct w_node * essid_root(struct w_node *tmp, int tasktype)
#if 0
{
	struct w_node *hash_find_node = NULL;
	static __u8 essid_number = 0;
	
	switch(tasktype){
		case ESSID_AP_ROOT_ADD:
			if(!tmp) return NULL;
			if(memcmp(tmp->ssid , "\x00\x00\x00\x00\x00\x00", 2) == 0){
				hash_find_node = (struct w_node *)hash_find(wlist_hash_table, 
					"hiding_ssid_wips!", 0);
			}else{
				hash_find_node = (struct w_node *)hash_find(wlist_hash_table, 
					(const char *)tmp->ssid, 0);
			}
			if(!hash_find_node){
				hash_find_node = (struct w_node *)XMALLOC(MTYPE_WIPS_DEBUG_ESSID_OF_HASH_NODE,sizeof(struct w_node));
				if(!hash_find_node){
					WIPSD_DEBUG("malloc for new essid_root err!\n");
					return NULL;
				}
				memcpy(hash_find_node, tmp, sizeof(struct w_node));
				memcpy(hash_find_node->essid_id, SSID_SEQUENCE_HEAD, 5);
				if( hash_insert(wlist_hash_table, (const char *)hash_find_node->ssid, 0, 
					(void *)hash_find_node) == NULL){
					essid_number++;
					hash_find_node->essid_id[5] = essid_number;
					if( hash_insert(wlist_hash_table, (const char *)hash_find_node->essid_id, 6, 
						(void *)hash_find_node) == NULL){
						hash_find_node->child_num++;
						hash_find_node->ssidtree_pap = tmp;
						tmp->ssidtree_pap = NULL;
						tmp->ssidtree_lastap = tmp->ssidtree_root = hash_find_node;
					}
				}
			}else{
				struct w_node *old_pap = NULL;
				old_pap = hash_find_node->ssidtree_pap;
				hash_find_node->child_num++;
				hash_find_node->ssidtree_pap = tmp;
				tmp->ssidtree_lastap = tmp->ssidtree_root = hash_find_node;
				tmp->ssidtree_pap = old_pap;
				if(old_pap)old_pap->ssidtree_lastap = tmp;
			}
			break;
		case ESSID_AP_ROOT_DEL:
			if(!tmp){
				return NULL;
			}else{
				struct w_node *old_pap = NULL;
				struct w_node *old_lastap = NULL;
				struct w_node *root = tmp->ssidtree_root;
				if(!root)return NULL;
				old_pap = tmp->ssidtree_pap;
				old_lastap = tmp->ssidtree_lastap;
				if(old_lastap){
					old_lastap->ssidtree_pap = old_pap;
				}
				if(old_pap)old_pap->ssidtree_lastap = old_lastap;
				if(root->child_num) root->child_num--;
			}
			break;
		case GET_ESSID_AP_ROOT_BY_NAME:
			hash_find_node = (struct w_node *)hash_find(wlist_hash_table, 
				(const char *)tmp->ssid, 0);
			return hash_find_node;
			break;
		case GET_ESSID_AP_ROOT_BY_ID:{
			if(tmp->essid_id[5] > essid_number ) return NULL;
			hash_find_node = (struct w_node *)hash_find(wlist_hash_table, 
				(const char *)tmp->essid_id, 6);
			return hash_find_node;}
			break;
		case GET_ESSID_ID_NUMBER:
			if(!tmp) return NULL;
			tmp->child_num = essid_number;
			return tmp;
		default :
			return NULL;
	}
	return NULL;
}
#else
{
return NULL;
}
#endif
#if 0
int tree_ap_ssid_change(struct w_node *node)
{
	w_node_list * p_oflist=NULL;
	if(!node)return -1;
	p_oflist = (w_node_list * )hash_find(wlist_hash_table, 
		(const char *)node->mac, 6);
	if(p_oflist){
		essid_root(node, ESSID_AP_ROOT_DEL);
		essid_root(&p_oflist->b_frame, ESSID_AP_ROOT_ADD);
		return 0;
	}else{
		return -1;
	}
}

int tree_ap_channel_change(struct w_node *node)
{
	w_node_list * p_oflist=NULL;
	if(!node)return -1;
	p_oflist = (w_node_list * )hash_find(wlist_hash_table, 
		(const char *)node->mac, 6);
	if(p_oflist){
		channel_root(&p_oflist->b_frame, CHANNEL_AP_ROOT_DEL, node->channel);
		channel_root(&p_oflist->b_frame, CHANNEL_AP_ROOT_ADD, p_oflist->b_frame.channel);
		return 0;
	}else{
		return -1;
	}
}

int tree_sta_bssid_change(struct w_node *node)
{
	w_node_list * p_oflist=NULL;
	__u8 bssid[6];//MAC

	if(!node)return -1;
	p_oflist = (w_node_list * )hash_find(wlist_hash_table, 
		(const char *)node->mac, 6);
	if(p_oflist){
		memcpy(bssid, p_oflist->b_frame.bssid, 6);
		memcpy(p_oflist->b_frame.bssid, node->bssid, 6);
		channel_root(&p_oflist->b_frame, CHANNEL_STA_ROOT_DEL, p_oflist->b_frame.channel);
		memcpy(p_oflist->b_frame.bssid, bssid, 6);
		channel_root(&p_oflist->b_frame, CHANNEL_STA_ROOT_ADD, p_oflist->b_frame.channel);
		return 0;
	}else{
		return -1;
	}
}

int tree_sta_channel_change(struct w_node *node)
{
	w_node_list * p_oflist=NULL;
	if(!node)return -1;
	p_oflist = (w_node_list * )hash_find(wlist_hash_table, 
		(const char *)node->mac, 6);
	if(p_oflist){
		channel_root(&p_oflist->b_frame, CHANNEL_STA_ROOT_DEL, node->channel);
		channel_root(&p_oflist->b_frame, CHANNEL_STA_ROOT_ADD, p_oflist->b_frame.channel);
		return 0;
	}else{
		return -1;
	}
}

int tree_get_essid_name_id(ListBuf * treebuf)
{
	struct w_node * root;
	struct w_node node;
	int node_len,buf_maxlen;
	__u8 i, essid_number;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	root = essid_root(&node, GET_ESSID_ID_NUMBER);
	essid_number = node.child_num;
	if(essid_number <= 0)return 0;
	memcpy(node.essid_id, SSID_SEQUENCE_HEAD, 5);
	for(i = 1; i<= essid_number; i++){
		node.essid_id[5] = i;
		root = essid_root(&node, GET_ESSID_AP_ROOT_BY_ID);

		if(root != NULL && (buf_maxlen - treebuf->len) >= node_len){
			memcpy( &treebuf->buf[treebuf->len], root, node_len);
			treebuf->len += node_len;
		}else{
			return 1;
		}
	}

	return 1;
}

int tree_get_by_essid_id(ListBuf * treebuf, struct w_node *node)
{
	struct w_node * root;
	struct w_node * sta;
	int node_len,buf_maxlen;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	root = essid_root(node, GET_ESSID_AP_ROOT_BY_ID);
	if(!root)return 0;
	root = root->ssidtree_pap;

	while(root){
		if( (buf_maxlen - treebuf->len) >= node_len){
			memcpy( &treebuf->buf[treebuf->len], root, node_len);
			treebuf->len += node_len;
		}else{
			return 1;
		}
		sta = root->psta;
		while(sta){
			if( (buf_maxlen - treebuf->len) >= node_len){
				memcpy( &treebuf->buf[treebuf->len], sta, node_len);
				treebuf->len += node_len;
			}else{
				return 1;
			}
			sta = sta->psta;
		}
		root = root->ssidtree_pap;
	}

	return 1;
}

int tree_get_by_a_essid(ListBuf * treebuf, struct w_node *node)
{
	struct w_node * root;
	struct w_node * sta;
	int node_len,buf_maxlen;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	root = essid_root(node, GET_ESSID_AP_ROOT_BY_NAME);
	if(!root)return 0;
	root = root->ssidtree_pap;

	while(root){
		if( (buf_maxlen - treebuf->len) >= node_len){
			memcpy( &treebuf->buf[treebuf->len], root, node_len);
			treebuf->len += node_len;
		}else{
			return 1;
		}
		sta = root->psta;
		while(sta){
			if( (buf_maxlen - treebuf->len) >= node_len){
				memcpy( &treebuf->buf[treebuf->len], sta, node_len);
				treebuf->len += node_len;
			}else{
				return 1;
			}
			sta = sta->psta;
		}
		root = root->ssidtree_pap;
	}

	return 1;
}
#endif
#if 0
int add_block_node_by_blocklist(int pid, struct w_node *sta, __u8* bssid, int channel, int freq_band);
int block_sta_with_a_essid(struct w_node *node)
{
	struct w_node * root;
	char mac[24], bssid[24];

	if(!node)return 0;
	root = essid_root(node, GET_ESSID_AP_ROOT_BY_NAME);
	if(!root)return 0;
	root = root->ssidtree_pap;

	sprintf(mac, MACSTR, MAC2STR(node->mac));
	while(root){
		if(memcmp( root->mac, node->bssid, 6) != 0 && root->signal > -90){
			sprintf(bssid, MACSTR, MAC2STR(root->mac));
			add_block_node_by_blocklist(0, node, root->mac, root->channel, root->freq_band);
		}
		root = root->ssidtree_pap;
	}

	return 1;
}

int tree_get_all_essid(ListBuf * treebuf)
{
	struct w_node * root;
	struct w_node * sta;
	struct w_node node;
	int node_len,buf_maxlen;
	__u8 i, essid_number;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	root = essid_root(&node, GET_ESSID_ID_NUMBER);
	essid_number = node.child_num;
	if(essid_number <= 0)return 0;
	memcpy(node.essid_id, SSID_SEQUENCE_HEAD, 5);
	for(i = 1; i<= essid_number; i++){
		node.essid_id[5] = i;
		root = essid_root(&node, GET_ESSID_AP_ROOT_BY_ID);
		if(!root && i==0){
			return 0;
		}else if(!root){
			return 1;
		}
		root = root->ssidtree_pap;

		while(root){
			if( (buf_maxlen - treebuf->len) >= node_len){
				memcpy( &treebuf->buf[treebuf->len], root, node_len);
				treebuf->len += node_len;
			}else{
				return 1;
			}
			sta = root->psta;
			while(sta){
				if( (buf_maxlen - treebuf->len) >= node_len){
					memcpy( &treebuf->buf[treebuf->len], sta, node_len);
					treebuf->len += node_len;
				}else{
					return 1;
				}
				sta = sta->psta;
			}
			root = root->ssidtree_pap;
		}
	}

	return 1;
}

int tree_get_by_channel(ListBuf * treebuf, struct w_node *node)
{
	struct w_node * root;
	struct w_node * sta;
	int node_len,buf_maxlen;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	root = channel_root(NULL, GET_CHANNEL_AP_ROOT, node->channel);
	if(!root)return 0;
	root = root->pap;

	while(root){
		if( (buf_maxlen - treebuf->len) >= node_len){
			memcpy( &treebuf->buf[treebuf->len], root, node_len);
			treebuf->len += node_len;
		}else{
			return 1;
		}
		sta = root->psta;
		while(sta){
			if( (buf_maxlen - treebuf->len) >= node_len){
				memcpy( &treebuf->buf[treebuf->len], sta, node_len);
				treebuf->len += node_len;
			}else{
				return 1;
			}
			sta = sta->psta;
		}
		root = root->pap;
	}

	return 1;
}
#endif
int channel_num(int i)
{
	i++;
	switch(i){
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
			return i;
		case 15:
			return 36;
		case 16:
			return 40;
		case 17:
			return 44;
		case 18:
			return 48;
		case 19:
			return 52;
		case 20:
			return 56;
		case 21:
			return 60;
		case 22:
			return 64;
		case 23:
			return 149;
		case 24:
			return 153;
		case 25:
			return 157;
		case 26:
			return 161;
		case 27:
			return 165;
		default:
			return 0;
	}

}
#if 0
int tree_get_all_channel(ListBuf * treebuf)
{
	struct w_node * root;
	struct w_node * sta;
	int node_len,buf_maxlen;
	int i;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	for(i = 0; i< CHANNEL_NUMBER; i++){
		root = channel_root(NULL, GET_CHANNEL_AP_ROOT, channel_num(i));
		if(!root) continue;
		root = root->pap;

		while(root){
			if( (buf_maxlen - treebuf->len) >= node_len){
				memcpy( &treebuf->buf[treebuf->len], root, node_len);
				treebuf->len += node_len;
			}else{
				return 1;
			}
			sta = root->psta;
			while(sta){
				if( (buf_maxlen - treebuf->len) >= node_len){
					memcpy( &treebuf->buf[treebuf->len], sta, node_len);
					treebuf->len += node_len;
				}else{
					return 1;
				}
				sta = sta->psta;
			}
			root = root->pap;
		}
	}

	return 1;
}
#endif
int tree_get_islandsta_by_channel(ListBuf * treebuf, struct w_node *node)
{
	struct w_node * root;
	int node_len,buf_maxlen;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	root = channel_root(NULL, GET_CHANNEL_STA_ROOT, node->channel);
	if(!root)return 0;
	root = root->psta;

	while(root){
		if( (buf_maxlen - treebuf->len) >= node_len){
			memcpy( &treebuf->buf[treebuf->len], root, node_len);
			treebuf->len += node_len;
		}else{
			return 1;
		}
		root = root->psta;
	}

	return 1;
}

int tree_get_islandsta_all_channel(ListBuf * treebuf)
{
	struct w_node * root;
	int node_len,buf_maxlen;
	int i;
	node_len = sizeof(struct w_node);
	buf_maxlen = LISTBUF_MAX;

	for(i = 0; i< CHANNEL_NUMBER; i++){
		root = channel_root(NULL, GET_CHANNEL_STA_ROOT, channel_num(i));
		if(!root) continue;
		root = root->psta;

		while(root){
			if( (buf_maxlen - treebuf->len) >= node_len){
				memcpy( &treebuf->buf[treebuf->len], root, node_len);
				treebuf->len += node_len;
			}else{
				return 1;
			}
			root = root->psta;
		}
	}
	return 1;
}



