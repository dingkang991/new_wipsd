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
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include "hash.h"
#include "ieee80211.h"
#include "wipsd_wnode.h"
#include "wipsd.h"
#include "checklist.h"

extern int report_wips_event(struct w_node *node, int event);
extern int clear_wips_event(struct w_node *node, int event);
extern __u32 test_wevent_bitmap(int eid, __u32 (*ev_map)[ALERT_LEN] );
extern struct hash_control *wlist_hash_table;
extern int maybe_fishing_ap(struct w_node * exist);
extern char *find_lan_ip(char *mac, char **ip);

#define NMACQUAD_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define NMACQUAD(addr) \
	((unsigned char *)addr)[0], \
	((unsigned char *)addr)[1], \
	((unsigned char *)addr)[2], \
	((unsigned char *)addr)[3], \
	((unsigned char *)addr)[4], \
	((unsigned char *)addr)[5]

/*======================================================================================*/
#if 0
//rulelist(hash)
struct hash_control *feature_list_hash_table;
pthread_mutex_t feature_hash_lock = PTHREAD_MUTEX_INITIALIZER;

void create_fea_hash(void)
{
	//create hash table
	if ((feature_list_hash_table = hash_new_bysize(1021)) == NULL){
		WIPSD_DEBUG("hash_new failed");
	}
}

int add_feature2hash(void * feature_node, const char * rule_name)
{
	//add the feature to table list by name
	pthread_mutex_lock(&feature_hash_lock);
	if( hash_insert(feature_list_hash_table, rule_name, 0, feature_node) == NULL){
		pthread_mutex_unlock(&feature_hash_lock);
		return 0;
	}
	pthread_mutex_unlock(&feature_hash_lock);
	return -1;
}

void * get_feature8hash(const char * rule_name)
{
	//get the feature from table list by name
	void * feature_node =NULL;

	pthread_mutex_lock(&feature_hash_lock);
	feature_node = hash_find(feature_list_hash_table, rule_name, 0);
	pthread_mutex_unlock(&feature_hash_lock);
	return feature_node;
}

int del_feature(const char * rule_name)
{
	//del the feature to table list by name
	void * tmppp = NULL;

	pthread_mutex_lock(&feature_hash_lock);
	tmppp = hash_find(feature_list_hash_table, rule_name, 0);
	if(tmppp){
		switch(rule_name){
			case "XXX":
				wipsd_free( ( XXX * )tmppp );
				break;
		}
		hash_delete(feature_list_hash_table, rule_name, 0, 0);
	}
	pthread_mutex_unlock(&feature_hash_lock);
}
#endif
/*======================================================================================*/

pollfunc * funclist = NULL;

/*======================================================================================*/
struct hash_control *internal_ssid_hash_table;

fea_ssid * internal_ssid =NULL;
//func
int find_internal_ssid(char *ssid)
{
	if(	hash_find(internal_ssid_hash_table, (const char *)ssid, 0) != NULL){
		return(1);
	}else{
		return(0);
	}
}

int check_f_ssid(struct w_node * wnode)
{
	if (wnode->node_type & 0x01)
    {//ext

        char *ip=NULL;
        char mac_str[20];
        sprintf(mac_str, MACSTR, MAC2STR(wnode->bssid));
        find_lan_ip(mac_str, &ip);
        if(ip)
        {
            clear_wips_event(wnode, WIPS_EID_FISHING_AP);
            XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
            return 0;
        }

		if(find_internal_ssid(wnode->ssid) &&  maybe_fishing_ap(wnode))
        {
            clear_wips_event(wnode, WIPS_EID_FISHING_AP);
			report_wips_event(wnode, WIPS_EID_FISHING_AP);
		}
	}
	return 0;
}

int check_proxy_ap(struct w_node * wnode)
{
    char *ip=NULL;
    char mac_str[20];
    sprintf(mac_str, MACSTR, MAC2STR(wnode->bssid));
    find_lan_ip(mac_str, &ip);
    if(ip)
    {
        clear_wips_event(wnode, WIPS_EID_STA_PROXY_AP);
        XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
        return 0;
    }
	if((wnode->node_type & 0x01) && (wnode->node_type & 0x02) && (memcmp(wnode->mac, wnode->bssid, 6) == 0))
    {
        clear_wips_event(wnode, WIPS_EID_STA_PROXY_AP);
		report_wips_event(wnode, WIPS_EID_STA_PROXY_AP);
	}

    return 0;
}
#if 0
int check_relay_unauth_ap(struct w_node * wnode)
{
    //char mac_str[32];

    if (!(wnode->node_type & 0x02))
        return 0;
    
    //memset(mac_str, 0, sizeof(mac_str));
    //sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", MAC2STR(wnode->mac));

	if(wnode->is_arp_added)
	{
		struct w_node_list * tmp=NULL;
		tmp = (w_node_list * )hash_find(wlist_hash_table, (const char *)wnode->bssid, 6);
		if ((tmp != NULL) && (tmp->b_frame.node_type & 0x1))
		{
            char *ip=NULL;
            char mac_str[20];
            sprintf(mac_str, MACSTR, MAC2STR(wnode->bssid));
            find_lan_ip(mac_str, &ip);
            if(ip)
            {
                clear_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
                XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
                return 0;
            }
			if (tmp->b_frame.internal_node != TRUE)
			{
                clear_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
				report_wips_event(&(tmp->b_frame), WIPS_EID_UNAUTH_AP);
                wnode->is_arp_added = 0;
			}
		}
	}

    return 0;
}
#endif
int check_nat_unauth_ap(struct w_node * wnode)
{
    char *ip=NULL;
    char mac_str[20];
    sprintf(mac_str, MACSTR, MAC2STR(wnode->bssid));
    find_lan_ip(mac_str, &ip);
    if(ip)
    {
        clear_wips_event(wnode, WIPS_EID_UNAUTH_AP);
        XFREE(MTYPE_WIPS_DEBUG_FIND_LAN_IP,ip);
        return 0;
    }
    if(wnode->nat_dev == 1)
    {
        clear_wips_event(wnode, WIPS_EID_UNAUTH_AP);
        report_wips_event(wnode, WIPS_EID_UNAUTH_AP);
    }

    return 0;
}

int add_internal_ssid(char * ssidname, fea_ssid ** i_ssid)
{
	fea_ssid * tmpp = NULL;
	fea_ssid * tmppp = NULL;

	if(!ssidname) return -1;
	if(ssidname[0] == '\0') return -1;
	if(hash_find(internal_ssid_hash_table, (const char *)ssidname, 0) != NULL){
		XFREE(MTYPE_WIPS_DEBUG_SSID_BUF,ssidname);
		return 0;
	}

	tmppp = *i_ssid;

	tmpp = XMALLOC(MTYPE_WIPS_DEBUG_FEA_SSID,sizeof(struct fea_ssid));
	if(tmpp == NULL){
		WIPSD_DEBUG("malloc for new pollfunc_node err!\n");
		XFREE(MTYPE_WIPS_DEBUG_SSID_BUF,ssidname);
		return -1;
	}
	memset(tmpp,0,sizeof(fea_ssid));
	tmpp->ssid = ssidname;

	if(!tmppp){
		*i_ssid = tmpp;
	}else{
		while(1){
			if(memcmp( ssidname,tmppp->ssid,SSID_BUFSIZE_D) == 0){
				XFREE(MTYPE_WIPS_DEBUG_SSID_BUF,ssidname);
				XFREE(MTYPE_WIPS_DEBUG_FEA_SSID,tmpp);
				return 0;
			}
			
			if(tmppp->next){
				tmppp = tmppp->next;
			}else{
				break;
			}
		}
		tmppp->next = tmpp;
	}
	hash_insert(internal_ssid_hash_table, (const char *)tmpp->ssid, 0, 
		(void *)tmpp);
	return 0;
}
/*======================================================================================*/

static int add_func( int (*check_function)(struct w_node * wnode) )
{
	pollfunc * tmpp = NULL;
	pollfunc * tmppp = NULL;

	if(!check_function) return(-1);
	tmppp = funclist;

	tmpp = malloc(sizeof(pollfunc));
	if(tmpp == NULL){
		WIPSD_DEBUG("malloc for new pollfunc_node err!\n");
		return -1;
	}
	memset(tmpp,0,sizeof(pollfunc));
	tmpp->check_func = check_function;

	if(!tmppp){
		funclist = tmpp;
	}else{
		while(tmppp->next){
			tmppp = tmppp->next;
		}
		tmppp->next = tmpp;
	}
	return 0;
}

void init_pollnode(void)
{
	//init hash table
	if ((internal_ssid_hash_table = hash_new()) == NULL)
		WIPSD_DEBUG("init_pollnode hash_new failed");

	//init funclist
	add_func(check_f_ssid);// fish ap
    add_func(check_proxy_ap);// proxy ap
    //add_func(check_relay_unauth_ap);// relay ap
    add_func(check_nat_unauth_ap);// nat ap
}

int pollingnode(struct w_node * wnode)
{
	pollfunc * tmppp = NULL;
	int ret =0;
	tmppp = funclist;
	while(tmppp){
		if(tmppp->check_func){
			ret = (* tmppp->check_func)(wnode);
			//if(ret != 0) return ret;
		}
		tmppp = tmppp->next;
	}
	return 0;
}

