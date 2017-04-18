/*
 * Wireless LAN (IEEE 802.11) link-layer frame sniffer
 * Copyright (c) 2010-, Security River Corp
 */
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
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include "ieee80211.h"
#include "wipsd_wnode.h"
#include "wipsd.h"
#include "debug.h"

typedef struct
{
	__u8 name[8];//
	long fd;//
	struct ifreq ifr;//
	struct sockaddr_ll addr;
	struct iwreq wrq;
	//rate,channel,txpower,
}interface_wlan;
int send_number=0;
int send_err_num=0;

#define SIOCSIWRATE			 0x8B20  /* set default bit rate (bps) */
#define IW_BITRATE_UNICAST	  0x0001  /* Maximum/Fixed unicast bitrate */
#define IW_BITRATE_BROADCAST	0x0002  /* Fixed broadcast bitrate */
#define INDEX_RATE			  12

#if 1
void deauth_blocking(interface_wlan *piface,__u8 *pds,__u8 *psa,__u8 *pbssid, 
						long rate, short seq, __u8 reason, short method)
{

	int ret, fromlen;
	fromlen = sizeof(struct sockaddr_ll);
	deauthenticate_type deauth;

	if(rate != BLOCKING_FIXED_RATE){
		if(rate == 0){
			piface->wrq.u.bitrate.fixed = 0;
		}else{
			piface->wrq.u.bitrate.fixed = 1;
		}
		piface->wrq.u.bitrate.value = (long) rate*MEGA/10;
		piface->wrq.u.bitrate.flags |= IW_BITRATE_UNICAST;
		if (ioctl(piface->fd, SIOCSIWRATE, &piface->wrq) != 0){
			WIPSD_DEBUG("Incorrect rate!\n");
			WIPSD_DEBUG("Supported rate -- 1|2|5.5|11|6|9|12|18|24|36|48|54 \n");
			return ;
		}
	}

	memset(&deauth,0,sizeof(deauth));
	deauth.fc[0]=0xC0;
	deauth.du[0]=0x75;//0x75;
	deauth.du[1]=0;//0x00;
	if(seq <= 0){
		deauth.sc[0]=0x40;
		deauth.sc[1]=0x0A;
	}else{
	  deauth.sc[0] = (seq % 0x10)<<4;//seq / 0x100;
	    deauth.sc[1] = seq / 0x10;
	}
	deauth.reason_code[1]=0x00;
#if 0
	//normally
	memcpy( deauth.ds, pds , 6);
	memcpy( deauth.sa, psa , 6);
	memcpy( deauth.bssid, pbssid , 6);
	if(deauth.ds[0] != deauth.bssid[0] ||
	   deauth.ds[1] != deauth.bssid[1] ||
	   deauth.ds[2] != deauth.bssid[2] ||
	   deauth.ds[3] != deauth.bssid[3] ||
	   deauth.ds[4] != deauth.bssid[4] ||
	   deauth.ds[5] != deauth.bssid[5] ){//FromDS
		deauth.fc[1]=WLAN_FC_FROMDS;
		deauth.reason_code[0]=0x05;
	}else{//ToDS
		deauth.fc[1]=WLAN_FC_TODS;
		deauth.reason_code[0]=0x03;
	}
	ret = sendto(piface->fd, (__u8 *)&deauth, sizeof(deauth), 0, 
		(struct sockaddr *)&piface->addr, sizeof(struct sockaddr_ll));
#else
	ret = sendto(piface->fd, "\x00", 1, 0, (struct sockaddr *)&piface->addr, sizeof(struct sockaddr_ll));
	//sta to ap
	if(method & 0x05){
		memcpy( deauth.ds, pbssid , 6);//memcpy( deauth.ds, pds , 6);
		memcpy( deauth.sa, psa , 6);
		memcpy( deauth.bssid, pbssid , 6);
		
		deauth.fc[1]=0;
		deauth.reason_code[0]=0x6; //reason;
		
		ret = sendto(piface->fd, (__u8 *)&deauth, sizeof(deauth), 0, 
			(struct sockaddr *)&piface->addr, sizeof(struct sockaddr_ll));
#if 0
		WIPSD_DEBUG("method & 0x05	ret[%d]	pds[%02x:%02x:%02x:%02x:%02x:%02x]	psa[%02x:%02x:%02x:%02x:%02x:%02x]\n",
			ret, 
			deauth.ds[0], deauth.ds[1], deauth.ds[2], deauth.ds[3], deauth.ds[4], deauth.ds[5], 
			deauth.sa[0], deauth.sa[1], deauth.sa[2], deauth.sa[3], deauth.sa[4], deauth.sa[5]);
		if(ret == -1)perror("Fail to sendto x01");
#endif
if(ret > 0)send_number++;
else send_err_num++;
	}
	//ap to sta
	if(method & 0x06) {
		memcpy( deauth.ds, psa , 6);
		memcpy( deauth.sa, pbssid , 6);//memcpy( deauth.sa, pds , 6);
		memcpy( deauth.bssid, pbssid , 6);

		deauth.fc[1]=0;
		deauth.reason_code[0]=0x1; //reason;

		ret = sendto(piface->fd, (__u8 *)&deauth, sizeof(deauth), 0, 
			(struct sockaddr *)&piface->addr, sizeof(struct sockaddr_ll));
if(ret > 0)send_number++;
else send_err_num++;
	}
#endif
}

static arp_type arppkt;
void arp_attack_blocking(interface_wlan *piface, __u8 *bssid, __u8 *psrcmac, __u8 *pdstmac,
						__u8 *psrcip, __u8 *pdstip, int istods)
{
  int ret;
		  
  if( memcmp(psrcip, "\x00\x00\x00\x00", 4)==0){
     return;
   }
	memset(&arppkt,0,sizeof(arppkt));
	arppkt.fc[0]=0x08;
	arppkt.fc[1]=0x00;	
	arppkt.du[0]=0x70;
	arppkt.du[1]=0x00;
	memcpy(arppkt.LLC, "\xaa\xaa\x03", 3);
	memcpy(arppkt.protocol, "\x08\x06", 2);
	memcpy(arppkt.hardware, "\x00\x01", 2);
	memcpy(arppkt.protocol2, "\x08\x00", 2);
	arppkt.hwaddrlen	=	6;
	arppkt.pcaddrlen	=	4;	
	memcpy(arppkt.operation, "\x00\x02", 2);	 //response
	//cheat dst
	//1?2£¤¡À¡§??
	memcpy( arppkt.srchwaddr, psrcmac , 6);//wrong mac use psrcmac
	arppkt.srchwaddr[3] = 0x80;//arppkt.srchwaddr[0]<<1;
	arppkt.srchwaddr[4] = 0xF8;//arppkt.srchwaddr[1]<<1;
	arppkt.srchwaddr[5] = 0xEB;//arppkt.srchwaddr[2]<<1;
	memcpy( arppkt.srcpcaddr, psrcip , 4);
	memcpy( arppkt.dsthwaddr, "\xff\xff\xff\xff\xff\xff" , 6);//right mac
	memcpy( arppkt.dstpcaddr, "\xff\xff\xff\xff" , 4);
	memcpy( arppkt.fcs, "\x55\xaa\x55\xaa" , 4);

	if(istods){
		arppkt.fc[1] = 0x01;
		memcpy( arppkt.mac1, bssid, 6);
		memcpy( arppkt.mac2, psrcmac, 6);//¡À?D?¨º?AP¨¨?¨º?¦Ì?mac !
		memcpy( arppkt.mac3, pdstmac, 6);
	}else{
		arppkt.fc[1] = 0x02;
		memcpy( arppkt.mac1, pdstmac, 6);
		memcpy( arppkt.mac2, bssid, 6);
		memcpy( arppkt.mac3, arppkt.srchwaddr, 6); // ¡À?D?o¨ª¨¦?2?mac¨°???!
	}
	ret = sendto(piface->fd, (__u8 *)&arppkt, sizeof(arppkt), 0, 
		(struct sockaddr *)&piface->addr, sizeof(struct sockaddr_ll));
	if(ret > 0)send_number++;
	else send_err_num++;
	//	WIPSD_DEBUG("send %d bytes!\n", ret);
}
#else
void deauth_blocking(const char *iface,__u8 *pds,__u8 *psa,__u8 *pbssid, long rate, short seq, short method)
{
#define SIOCSIWRATE			 0x8B20  /* set default bit rate (bps) */
#define IW_BITRATE_UNICAST	  0x0001  /* Maximum/Fixed unicast bitrate */
#define IW_BITRATE_BROADCAST	0x0002  /* Fixed broadcast bitrate */
#define INDEX_RATE			  12
	struct iwreq	  wrq;
//	short rate_c[INDEX_RATE][2]={{1,10},{1,20},{1,55},{1,110},{1,60},
//		{1,90},{1,120},{1,180},{1,240},{1,360},{1,480},{1,540}};
	deauthenticate_type deauth;
	int s;
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int ret;

	if(!(iface && pds && psa && pbssid)){
		WIPSD_DEBUG("NULL POINTER\n");
		exit(-1);
	}

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
	{
		perror("socket[PF_PACKET,SOCK_RAW]\n");
		exit(-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
	if (ioctl(s, SIOCGIFINDEX, &ifr) != 0)
	{
		perror("ioctl(SIOCGIFINDEX)\n");
		close(s);
		exit(-1);
	}
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
//	WIPSD_DEBUG("Opening raw packet socket for ifindex %d\n", addr.sll_ifindex);
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		perror("bind\n");
		close(s);
		exit(-1);
	}

	memset(&deauth,0,sizeof(deauth));
	deauth.fc[0]=0xC0;
	deauth.du[0]=0x75;
	deauth.du[1]=0x00;
	deauth.sc[0]=0x40;
	deauth.sc[1]=0x0A;

//    deauth.sc[0] = seq;
//    deauth.sc[1] = seq > 8;

	deauth.reason_code[1]=0x00;
	memcpy( deauth.ds, pds , 6);
	memcpy( deauth.sa, psa , 6);
	memcpy( deauth.bssid, pbssid , 6);

	deauth.fc[1]=WLAN_FC_TODS;
	deauth.reason_code[0]=0x03;

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", iface);

	if(rate == 0){
		wrq.u.bitrate.fixed = 0;
	}else{
		wrq.u.bitrate.fixed = 1;
	}
	wrq.u.bitrate.value = (long) rate*MEGA/10;
	wrq.u.bitrate.flags |= IW_BITRATE_UNICAST;
	if (ioctl(s, SIOCSIWRATE, &wrq) != 0){
		WIPSD_DEBUG("Incorrect rate!\n");
		WIPSD_DEBUG("Supported rate -- 1|2|5.5|11|6|9|12|18|24|36|48|54 \n");
			close(s);
			exit(-1);
	 }
    
//	ret = sendto(s, (__u8 *)&deauth, sizeof(deauth), MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
	deauth.fc[1]=0;
//  sta to ap
    if(method & 0x05)
    	ret = sendto(s, (__u8 *)&deauth, sizeof(deauth), MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));


//  ap to sta
    if(method & 0x06) {
    	memcpy( deauth.ds, psa , 6);
    	memcpy( deauth.sa, pds , 6);
    	memcpy( deauth.bssid, pbssid , 6);

    	deauth.fc[1]=WLAN_FC_FROMDS;
    	deauth.reason_code[0]=0x05;

    	deauth.fc[1]=0;

       	ret = sendto(s, (__u8 *)&deauth, sizeof(deauth), MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
    }

	close(s);
}

void usage(void)
{
	WIPSD_DEBUG("usage: blocking interface block_type dsMac saMac bssid rate\n");
	WIPSD_DEBUG("	   block_type	 -- sta (Only Supported sta now.)\n");
	WIPSD_DEBUG("	   Supported rate -- 1|2|5.5|11|6|9|12|18|24|36|48|54 \n\n");
}

__u8 atoix(__u8 * str)
{
	if(*str > 47 && *str < 58) return (*str - 48);
	if(*str > 64 && *str < 71) return (*str - 55);
	if(*str > 96 && *str < 103) return (*str - 87);
	WIPSD_DEBUG("\nPlease input mac address like that format 01:23:45:ab:cd:ef .\n\n");
	exit(-1);
}

void str2mac(__u8 * mac, char * str1)
{
	__u8 *  str = (__u8 * )str1;
	mac[0]=atoix(&str[0])*16 + atoix(&str[1]);
	mac[1]=atoix(&str[3])*16 + atoix(&str[4]);
	mac[2]=atoix(&str[6])*16 + atoix(&str[7]);
	mac[3]=atoix(&str[9])*16 + atoix(&str[10]);
	mac[4]=atoix(&str[12])*16 + atoix(&str[13]);
	mac[5]=atoix(&str[15])*16 + atoix(&str[16]);
//	WIPSD_DEBUG("mac : %02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

/*xxx start point*/
int main(int argc, char *argv[])
{
	const char *iface = NULL;
	__u8 ds[6];
	__u8 sa[6];
	__u8 bssid[6];
	long tx_rate=0;

	if( argc < 6 ) goto usage_and_exit;
	iface = argv[1];
	str2mac(ds,argv[3]);
	str2mac(sa,argv[4]);
	str2mac(bssid,argv[5]);
	tx_rate= (long) (atof(argv[6])*10);
	deauth_blocking(iface,ds,sa,bssid,tx_rate, atoi(argv[7]), atoi(argv[8]));
	return 0;
usage_and_exit:
	usage();
	return 0;
}
#endif
