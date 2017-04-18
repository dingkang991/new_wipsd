
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <zebra.h>
#include "fakeap.h"

#define IFACE5 "ath5"

static void iwconfigOPEN(char * ssid, char * iface, int ch)
{
	char cmd[255];
	int ret;

	sprintf(cmd, "ifconfig %s down", iface);
	ret = system(cmd);
	sprintf(cmd, "iwconfig %s essid \"%s\" channel %d key off", iface, ssid, ch);
	ret = system(cmd);
//	sprintf(cmd, "iwconfig %s key off", iface);
//	ret = system(cmd);
	sprintf(cmd, "ifconfig %s up", iface);
	ret = system(cmd);

}
#if 0
static void iwconfigWEP(char * ssid, char * iface, int ch)
{
	char cmd[255];
	int ret;

	sprintf(cmd, "ifconfig %s down", iface);
	ret = system(cmd);
	sprintf(cmd, "iwconfig %s essid \"%s\" channel %d key 1234567890", iface, ssid, ch);
	ret = system(cmd);
//	sprintf(cmd, "iwconfig %s key 1234567890", iface);
//	ret = system(cmd);
	sprintf(cmd, "ifconfig %s up", iface);
	ret = system(cmd);

}

static void setWEP(char * ssid, char * iface, int ch)
{
	char cmd[255];
	int ret;

	sprintf(cmd, "echo interface=%s > /tmp/%s_wep.conf", iface, iface);
	ret = system(cmd);
	sprintf(cmd, "echo driver=atheros >> /tmp/%s_wep.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo ssid=%s >> /tmp/%s_wep.conf", ssid, iface);
	ret = system(cmd);
	sprintf(cmd, "echo hw_mode=g >> /tmp/%s_wep.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo channel=%d >> /tmp/%s_wep.conf", ch, iface);
	ret = system(cmd);
	
	sprintf(cmd, "echo wep_default_key=0 >> /tmp/%s_wep.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo wep_key0=1234567890 >> /tmp/%s_wep.conf", iface);
	ret = system(cmd);

	sprintf(cmd, "/bin/hostapd /tmp/%s_wep.conf &", iface);
	ret = system(cmd);

}
static void setWPA(char * ssid, char * iface, int ch)
{
	char cmd[255];
	int ret;

	ret = system("killall hostapd; killall hostapd");
	sprintf(cmd, "echo interface=%s > /tmp/%s_wpa.conf", iface, iface);
	ret = system(cmd);
	sprintf(cmd, "echo driver=atheros >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo ssid=%s >> /tmp/%s_wpa.conf", ssid, iface);
	ret = system(cmd);
	sprintf(cmd, "echo hw_mode=g >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo channel=%d >> /tmp/%s_wpa.conf", ch, iface);
	ret = system(cmd);
	
	sprintf(cmd, "echo macaddr_acl=0 >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo auth_algs=1 >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo ignore_broadcast_ssid=0 >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo wpa=3 >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo wpa_passphrase=1234567890 >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo wpa_key_mgmt=WPA-PSK >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo wpa_pairwise=TKIP >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);
	sprintf(cmd, "echo rsn_pairwise=CCMP >> /tmp/%s_wpa.conf", iface);
	ret = system(cmd);

	sprintf(cmd, "/bin/hostapd /tmp/%s_wpa.conf &", iface);
	ret = system(cmd);

	sleep(5);
	sprintf(cmd, "iwconfig %s channel %d", iface, ch);
	ret = system(cmd);

}
#endif

void create_fakeap(char * iface, char * ssid, int ch, char type)
{
	char cmd[255];
	int ret;

	sprintf(cmd, "/sbin/ifconfig %s down && sleep 2", iface);
	ret = system(cmd);
	sprintf(cmd, "/usr/hls/bin/wlanconfig %s destroy && sleep 3", iface);
	ret = system(cmd);
	sprintf(cmd, "/usr/hls/bin/wlanconfig %s create wlandev wifi0 wlanmode ap nosbeacon && sleep 2", iface);
	ret = system(cmd);

	sleep(3);
	switch(type){
		case FAKE_WPA:
			iwconfigOPEN(ssid, iface, ch);
//			setWPA(ssid, iface, ch);
			break;
		case FAKE_WEP:
			iwconfigOPEN(ssid, iface, ch);
//			iwconfigWEP(ssid, iface, ch);
			break;
		case FAKE_OPEN:
			iwconfigOPEN(ssid, iface, ch);
			break;
		default:
			break;
	}

}

void auto_operating_fakeap(struct w_node * node, int init_mem)
{
#define FAKE_AP_NUM 16
	static created_ap ap[FAKE_AP_NUM];
	static int _init = 1;
	int i, sec_type;
	char iface[10];
	char cmd[255];
	int ret;

	if(_init || init_mem){
		_init = 0;
		memset(ap, 0, sizeof(created_ap)*FAKE_AP_NUM);
	}
	
	if(!node) 
		return;
	
	if(!(node->node_type & 1)) 
		return;
	
	if(node->ssid[0] == '\0') return;

	if(strcmp(node->sec_type,"open-system")==0){
		sec_type = FAKE_OPEN;
	}else if(strcmp(node->sec_type,"wep")==0){
		sec_type = FAKE_WEP;
	}else{
		sec_type = FAKE_WPA;
	}
	
	for(i=1; i<FAKE_AP_NUM; i++){
		if(node->child_num == ADD_AP){
			if(sec_type == ap[i].sec_type 
				&& strncmp( ap[i].ssid,node->ssid,sizeof(ap[i].ssid))==0){
				return;
			}
		}else{
			if(sec_type == ap[i].sec_type 
				&& strncmp( ap[i].ssid,node->ssid,sizeof(ap[i].ssid))==0){
				sprintf(cmd, "/sbin/ifconfig ath%d down", i);
				ret = system(cmd);
				sprintf(cmd, "/usr/hls/bin/wlanconfig ath%d destroy", i);
				ret = system(cmd);

				memset(&ap[i], 0, sizeof(created_ap));
			}
		}
	}
	if(node->child_num == ADD_AP){
		for(i=1; i<FAKE_AP_NUM; i++){
			if(ap[i].ssid[0] == '\0'){
				break;
			}
		}
		if(i > (FAKE_AP_NUM-1)) /*return;*/i = (FAKE_AP_NUM-1);
		memset(&ap[i], 0, sizeof(created_ap));
		strncpy( ap[i].ssid,node->ssid,sizeof(ap[i].ssid));
		ap[i].sec_type = sec_type;
		sprintf(iface, "ath%d", i);
		create_fakeap(iface, ap[i].ssid, node->channel, sec_type);
	}
}

