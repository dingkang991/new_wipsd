/**************************************************************
  * Desc: This file use for parsing dhcp packet and portal redirect
  * Author: lujing@raytight
  * Date: 2015/01/15
  **************************************************************/

#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <asm/unaligned.h>
//#include "ieee80211_node.h"
#include <ieee80211_var.h>
#include "ath_ald_external.h"
#include "rt_netlink.h"
#include "rt_webauth.h"

#define MAX_AUTH_URL_LEN    256 
#define MAX_PATH_LEN      	256
#define MAX_DOMAIN_LEN      50
#define MAX_URL_LEN        	MAX_DOMAIN_LEN+MAX_PATH_LEN+MAX_AUTH_URL_LEN


struct dhcp_device_option_t dhcp_device_option[] = 
{
	{OS_APPLE_IOS8,"Apple iOS8", 55, {0x01,0x03,0x06,0x0F,0x77,0xFC},6},
	{OS_ANDROID,"Android", 60, {0x64,0x68,0x63,0x70,0x63,0x64,0x20,0x34,0x2E,0x30,0x2E,0x31,0x35},13},
	{OS_BLACKBERRY,"Blackberry", 60 ,{0x42,0x6C,0x61,0x63,0x6B,0x42,0x65,0x72,0x72,0x79},10},
	{OS_WINDOWS_7_OR_VISTA,"Windows 7/ Vista Desktop", 55, {0x01,0x0f,0x03,0x06,0x2c,0x2e,0x2f,0x1f,0x21,0x79,0xf9,0x2b},12},
	{OS_WINDOWS_XP,"Windows XP(SP3, Home, Professional)", 55, {0x01,0x0f,0x03,0x06,0x2c,0x2e,0x2f,0x1f,0x21,0xf9,0x2b},11},
	{OS_WINDOWS_MOBILE,"Windows Mobile", 60, {0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x20,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x43,0x45,0x00},21},
	{OS_WINDOWS_7_PHONE,"Windows 7 Phone", 55, {0x01,0x03,0x06,0x0f,0x2c,0x2e,0x2f},7},
	{OS_APPLE_MAX_10_DOT_6_BELOW,"Apple Mac OSX (10.6 and below)", 55, {0x01,0x03,0x06,0x0f,0x77,0x5f,0xfc,0x2c,0x2e,0x2f},10},
	{OS_APPLE_MAX_10_DOT_7_UP,"Apple Mac OSX (10.7 and above)", 55, {0x01,0x03,0x06,0x0f,0x77,0x5f,0xfc,0x2c,0x2e},9},
    {OS_APPLE_IOS9,"Apple iOS9", 55, {0x01,0x79,0x03,0x06,0x0F,0x77,0xFC},7},
    {OS_ANDROID4,"Android 4.x", 55, {0x01,0x21,0x03,0x06,0x0f,0x1c,0x33,0x3a,0x3b},9},
    {OS_WINDOWS_10,"Windows 10", 55 ,{0x01,0x0f,0x03,0x06,0x2c,0x2e,0x2f,0x1f,0x21,0x79,0xf9,0xfc,0x2b},13},
    {OS_WINDOWS_10,"Windows 10", 55 ,{0x01,0x03,0x06,0x0f,0x1f,0x21,0x2b,0x2c,0x2e,0x2f,0x79,0xf9,0xfc},13}
};


/**************http portal redirect start*******************/
static char *strnstr_1(char *begin, char *end, char *str, int32_t str_len)
{
	int32_t i = 0;

	if (!begin || begin > end || !str  || str_len <= 0){
		goto error;
	}

	while (begin + i + str_len - 1 <= end){
		if (!strncmp(begin + i, str, str_len)){
			return (begin + i);
		}

		i++;
	}

error:
	return NULL;
}


u16 rt_tcp_v4_check(struct tcphdr *th, int len,
			       unsigned long saddr, unsigned long daddr, 
			       unsigned long base)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, IPPROTO_TCP, base));
}

static void rt_skb_create_ethhdr_payload(struct iphdr *iph,
				 struct tcphdr *tcph,
				 unsigned httplen,
				 struct iphdr *new_ip,
				 struct tcphdr *new_tcp,
				 unsigned inforlen,
				 struct ieee80211vap *vap)
{
	new_tcp->seq = tcph->ack_seq ;
    if (vap->iv_is_auto_portal)
        new_tcp->ack_seq = htonl(ntohl(tcph->seq) + ntohl(iph->tot_len) - 20 - ntohl(tcph->doff * 4));
    else
    	new_tcp->ack_seq = htonl(ntohl(tcph->seq) + httplen);
	*((__u16 *)(&(new_tcp->ack_seq) + 1)) = 0;
	new_tcp->ack = 1;
	new_tcp->psh = 1;
	new_tcp->fin = 1;
	
	/* 填充IP头部 */
    new_ip->ihl = 5;
    new_ip->version = 4;
	new_ip->tos = iph->tos;
    new_ip->id = iph->id;
    new_ip->frag_off = 0;
	new_ip->ttl = 64;
	new_ip->saddr = iph->daddr;
	new_ip->daddr = iph->saddr;
	new_ip->check = 0;
	new_ip->protocol = IPPROTO_TCP;
	new_ip->check = ip_fast_csum((u8 *)new_ip, new_ip->ihl);
	
	/* 填充TCP头部 */
	new_tcp->source = tcph->dest;
	new_tcp->dest = tcph->source;
	new_tcp->window = 0x0040;
	new_tcp->urg_ptr = 0;
	new_tcp->doff = 5;
	new_tcp->check = 0;
	new_tcp->check = rt_tcp_v4_check(new_tcp, 
									new_tcp->doff * 4 + inforlen,
									new_ip->saddr, 
									new_ip->daddr,	
									csum_partial((unsigned char *)new_tcp, new_tcp->doff * 4 + inforlen,0));
}


static void rt_skb_create_ack_payload(struct iphdr *iph,
				 struct tcphdr *tcph,
				 struct iphdr *new_ip,
				 struct tcphdr *new_tcp)
{
	new_tcp->seq = tcph->ack_seq ;
    new_tcp->ack_seq = htonl(ntohl(tcph->seq) + 1);
    
	*((__u16 *)(&(new_tcp->ack_seq) + 1)) = 0;
	new_tcp->ack = 1;
	new_tcp->syn = 1;
		
	/* 填充IP头部 */
    new_ip->ihl = 5;
    new_ip->version = 4;
	new_ip->tos = iph->tos;
    new_ip->id = iph->id;
    new_ip->frag_off = 0;
	new_ip->ttl = 64;
	new_ip->saddr = iph->daddr;
	new_ip->daddr = iph->saddr;
	new_ip->check = 0;
	new_ip->protocol = IPPROTO_TCP;
	new_ip->check = ip_fast_csum((u8 *)new_ip, new_ip->ihl);
	
	/* 填充TCP头部 */
	new_tcp->source = tcph->dest;
	new_tcp->dest = tcph->source;
	new_tcp->window = 0x3908;
	new_tcp->urg_ptr = 0;
	new_tcp->doff = 5;
	new_tcp->check = 0;
	new_tcp->check = rt_tcp_v4_check(new_tcp, 
									new_tcp->doff * 4,
									new_ip->saddr, 
									new_ip->daddr,	
									csum_partial((unsigned char *)new_tcp, new_tcp->doff * 4, 0));
}


static inline unsigned int rt_skb_create_httphdr(char * RdHeadMsg,
				    const char *auth_url,
				    const char *path,
				    const char *dom_name)
{
	char *head="HTTP/1.0 302 Moved Temporarily\r\nLocation:";
	char *tail="\r\nServer: SAC\r\n\r\n";
	unsigned int len = 0;

	len= strlen(head) + strlen(tail) + strlen(RdHeadMsg) + strlen(auth_url) + strlen(path) + strlen(dom_name);
	if (len >= MAX_URL_LEN)
	{
		return 1;
	}

	strcat(RdHeadMsg,head);
	strcat(RdHeadMsg,auth_url);
	strcat(RdHeadMsg,dom_name);
	strcat(RdHeadMsg,path);
	strcat(RdHeadMsg,tail);

	return 0;
}



/*************************************************
  函数名称：get_original_web_url
  函数描述：根据参数type,从一个http get请求包中取得相应的信息;
  输入参数说明?
  输出参数说明：
  函数返回值说明：取得信息成功返回1，否则返回0;
  其它说明：
*************************************************/

unsigned int get_original_web_url(const char *httphdr,char * domain_name, char * web_page_path)
{
#if 1
	char *p=NULL;
	unsigned int len;
	
	/*取得web页面对应的路径*/
	p=strstr(httphdr,"GET ")+4;	//定位到"GET "后的第一个字符
	len=0;
	while (*p!=' ' && len<MAX_PATH_LEN-1)
	{
		*web_page_path++=*p++;
		len++;
	}
	
	if (len>=MAX_PATH_LEN-1)
		goto error;
	else
		*web_page_path='\0';
	

	/*取得web页面所在web服务器的域名*/
	p=strstr(httphdr,"\r\nHost: ")+8;	//定位到"\r\nHost: "后的第一个字符
	len=0;
	while (*p!='\r' && len<MAX_DOMAIN_LEN-1)
	{
		*domain_name++=*p++;
		len++;
	}
	
	if (len>=MAX_DOMAIN_LEN-1)
		goto error;
	else
		*domain_name='\0';
	
	
	return 1;

error:
	return 0;
#else
			*domain_name='\0';
			return 1;
#endif
}


/*************************************************
  函数名称：rt_skb_get_httph
  函数描述：取得http数据报头部的首地址;
  输入参数说明：
  输出参数说明：
  函数返回值说明：存在数据报返回首地址，否则返回NULL;
  其它说明：
*************************************************/

inline char *rt_skb_get_httph(struct tcphdr *tcph,unsigned int tcph_len,unsigned int iph_len,unsigned int skb_len)
{
	unsigned int msglen= skb_len - (iph_len + tcph_len);	

	if (msglen)	//存在数据报
	{
		return (char *)((char *)tcph + tcph_len);
	}
	else
	{
		return NULL;
	}
}


inline int rt_skb_is_http_get(struct tcphdr *tcph, unsigned int tcph_len, unsigned int iph_len, unsigned int skb_len)
{
	char * httph = NULL;
	unsigned int len = 4;	//即"GET "的长度;
	unsigned int msg_len=skb_len-(iph_len+tcph_len);
	
	//printk(KERN_DEBUG"%s  tcph->ack=%d  tcph->syn=%d\n",__FUNCTION__,tcph->ack,tcph->syn);
	httph = rt_skb_get_httph(tcph,tcph_len,iph_len,skb_len);
	if (!httph) {
		if (tcph->syn) {
			return -2;
		} else {
			return -1;
		}	
	} 
	else if (tcph->ack && !(tcph->syn))		// 是tcp ack包
	{	
		if(msg_len>=len && 
			!strncmp(httph,"GET ",len) && 
			strnstr_1(httph, httph+msg_len-1,"\r\nHost: ",8))  //是特殊的http get包
			return 1;
	}

	return 0;
}


/*************************************************
  函数名称：rt_get_auth_url
  函数描述：取得认证页面的URL;
  输入参数说明：@dev:HTTP get请求包对应对应的入接口;
  输出参数说明：@url:认证页面的url
  函数返回值说明：取得成功返回1，否则返回0;
*************************************************/

unsigned int rt_skb_create_webauth_url(struct sk_buff *skb, 
										char *auth_url, 
										unsigned int sip,
										u8 *smac,
										struct ieee80211vap *vap)
{
	char usermac[18];
	char apmac[18];
	char wlanuserip[16];
	char c_portalid[6];
	char c_wlan_id[6];
	char c_radio_id[6];
	int radio_id = 0;
	int wlan_id = 0;
	int id = 0;
	struct net_device	*dev = NULL;
	struct ieee80211com *ic;
    
	if(!skb || !smac || !vap)
	{
		return 0;
	}
	
	// TODO: need to calculate 
	if ((strlen(vap->iv_portal_url) + 10) > MAX_AUTH_URL_LEN)		//strlen(":")+strlen("/?weburl=")==10
	{
		return 0;
	}

	//eg: https://192.168.0.61:2000/?usermac=00:21:45:C0:C1:81&wlanuserip=192.168.0.69&portal=1&weburl=http://www.msftncsi.com/ncsi.txt
	dev = skb->dev;
	//printk(KERN_DEBUG"*********%s******\n",dev->name);
	sscanf(dev->name, "ath%d", &id);
	if(id <= 16)
	{
		radio_id = 0;
		wlan_id = id;
	}
	else
	{
		radio_id = 1;
		wlan_id = id - radio_id * 18;
	}
	
	/*构造认证页面的url*/
	memset(usermac, 0, sizeof(usermac));
	memset(apmac, 0, sizeof(apmac));
	memset(wlanuserip,0,sizeof(wlanuserip));
	memset(c_portalid,0,sizeof(c_portalid));
	memset(c_wlan_id,0,sizeof(c_wlan_id));
	memset(c_radio_id,0,sizeof(c_radio_id));
	snprintf(usermac,sizeof(usermac),"%02X:%02X:%02X:%02X:%02X:%02X",
							smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
    if(radio_id)
    {
        ic = vap->iv_ic;
        snprintf(apmac,sizeof(apmac),"%02X:%02X:%02X:%02X:%02X:%02X",
            										ic->ic_myaddr[0],
            										ic->ic_myaddr[1],
            										ic->ic_myaddr[2],
            										ic->ic_myaddr[3],
            										ic->ic_myaddr[4],
            										(ic->ic_myaddr[5] - 16));
    }
    else
    {
	    snprintf(apmac,sizeof(apmac),"%02X:%02X:%02X:%02X:%02X:%02X",
        										vap->iv_my_hwaddr[0],
        										vap->iv_my_hwaddr[1],
        										vap->iv_my_hwaddr[2],
        										vap->iv_my_hwaddr[3],
        										vap->iv_my_hwaddr[4],
        										vap->iv_my_hwaddr[5]);
    }

	snprintf(wlanuserip,sizeof(wlanuserip),"%u.%u.%u.%u", 
										((unsigned char *)&sip)[0],
										((unsigned char *)&sip)[1],
										((unsigned char *)&sip)[2],
										((unsigned char *)&sip)[3]);
	snprintf(c_portalid,sizeof(c_portalid), "%d", vap->iv_portal_id);

	snprintf(c_wlan_id,sizeof(c_wlan_id), "%d", wlan_id);
	snprintf(c_radio_id,sizeof(c_radio_id), "%d", radio_id);

	strcat(auth_url, vap->iv_portal_url);

	strcat(auth_url,"/?usermac=");
	strcat(auth_url,usermac);

	strcat(auth_url,"&wlanuserip=");
	strcat(auth_url,wlanuserip);

	strcat(auth_url,"&portalid=");
	strcat(auth_url,c_portalid);

	strcat(auth_url,"&apmac=");
	strcat(auth_url,apmac);

	strcat(auth_url,"&wlan_id=");
	strcat(auth_url,c_wlan_id);

	strcat(auth_url,"&radio_id=");
	strcat(auth_url,c_radio_id);

	strcat(auth_url,"&weburl=");
	
	return 1;
}

void rt_skb_create_ethhdr(struct sk_buff *old_skb,struct sk_buff *new_skb)
{
	struct ethhdr *ethh_new = NULL;
	struct ethhdr *ethh_old = NULL;
	if(!old_skb || !new_skb)
	{
		return ;
	}

	ethh_old = eth_hdr(old_skb);
	ethh_new = (struct ethhdr*)skb_push(new_skb, sizeof(struct ethhdr));
	if(!ethh_old || !ethh_new)
	{
		return ;
	}
	
	memcpy(ethh_new->h_dest, ethh_old->h_source, ETH_ALEN);
	memcpy(ethh_new->h_source, ethh_old->h_dest, ETH_ALEN);
	ethh_new->h_proto = ethh_old->h_proto;
	
	return ;

}

void rt_skb_create(struct sk_buff *pskb, struct ieee80211vap *vap,struct iphdr *iph, struct tcphdr *tcph,u8 *httphdr)
{
	int skb_len = 0;
	struct sk_buff *skb = NULL;
	struct iphdr *new_iph = NULL;
	struct tcphdr *new_tcph = NULL;
	int httpmsg_len = 0;
	
	if(!pskb || !iph || !tcph || !httphdr)
	{
		return ;
	}

	httpmsg_len= ALIGN(strlen(httphdr), 4);
	skb_len = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + httpmsg_len);
	skb = dev_alloc_skb(skb_len);
	if(!skb)
	{
		return;
	}

	skb_reserve(skb, skb_len);
	skb_push(skb, httpmsg_len);
	memset(skb->data, 0, httpmsg_len);
	memcpy(skb->data, httphdr, httpmsg_len);
	new_tcph = (struct tcphdr*)skb_push(skb, sizeof(struct tcphdr));
	memset(new_tcph, 0, sizeof(struct tcphdr));
	new_iph = (struct iphdr*)skb_push(skb, sizeof(struct iphdr));
	memset(new_iph, 0, sizeof(struct iphdr));
	new_iph->tot_len = htons(skb->len);
	
	rt_skb_create_ethhdr_payload(iph,tcph,httpmsg_len,new_iph,new_tcph,httpmsg_len, vap);
	rt_skb_create_ethhdr(pskb, skb);

	skb->protocol = __constant_htons (ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb->len = skb_len;

	vap->iv_evtable->wlan_vap_xmit_queue(vap->iv_ifp, skb);

	return;
}


void rt_create_connect_skb(struct sk_buff *pskb, struct ieee80211vap *vap,struct iphdr *iph, struct tcphdr *tcph)
{
	int skb_len = 0;
	struct sk_buff *skb = NULL;
	struct iphdr *new_iph = NULL;
	struct tcphdr *new_tcph = NULL;
	
	if(!pskb || !iph || !tcph)
	{
		return ;
	}

	skb_len = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
	skb = dev_alloc_skb(skb_len);
	if(!skb)
	{
		return ;
	}

	skb_reserve(skb, skb_len);
	new_tcph = (struct tcphdr*)skb_push(skb, sizeof(struct tcphdr));
	memset(new_tcph, 0, sizeof(struct tcphdr));
	new_iph = (struct iphdr*)skb_push(skb, sizeof(struct iphdr));
	memset(new_iph, 0, sizeof(struct iphdr));
	new_iph->tot_len = htons(skb->len);
	
	rt_skb_create_ack_payload(iph, tcph, new_iph, new_tcph);
	rt_skb_create_ethhdr(pskb, skb);

	skb->protocol = __constant_htons (ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb->len = skb_len;

	vap->iv_evtable->wlan_vap_xmit_queue(vap->iv_ifp, skb);
	return ;
} 


/*************************************************
  函数名称：auth_redirect
  函数描述：捕获没有经过web认证的HTTP get包，并构造响应包;
*************************************************/
unsigned int rt_skb_webauth_redirect (struct sk_buff *skb, struct ieee80211_node *ni)
{
	int ret=0;
	unsigned int iph_len = 0;
	unsigned int tcph_len=0;
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL; 
	char *httph = NULL;
	char auth_url[MAX_AUTH_URL_LEN];
	char path[MAX_PATH_LEN];
	char dom_name[MAX_DOMAIN_LEN];
	char httphdr [MAX_URL_LEN];	
	char rd_url [MAX_URL_LEN];	
	char ipaddr1[16];
	char ipaddr2[16];
	u8 apmac[ETH_ALEN];

	if(!skb || (!ni && !ni->ni_vap))
	{
        printk(KERN_DEBUG"%s-%d:\n", __func__, __LINE__);
		return RX_DROP_UNUSABLE;
	}
	
	memset(auth_url,0,sizeof(auth_url));
	memset(path,0,sizeof(path));
	memset(dom_name,0,sizeof(dom_name));
	memset(rd_url,0,sizeof(rd_url));
	memset(ipaddr1,0,sizeof(ipaddr1));
	memset(ipaddr2,0,sizeof(ipaddr2));
	memset(apmac, 0, sizeof(apmac));
	eth = eth_hdr(skb);
	iph = (struct iphdr *)((u8 *)eth + sizeof(struct ethhdr));
	iph_len=iph->ihl * 4;
	tcph= (struct tcphdr*) ((char *)iph + iph_len);
	tcph_len=tcph->doff * 4;

	ret = rt_skb_is_http_get(tcph, tcph_len, iph_len, skb->len);
	if (ret > 0)/*is http get request*/
	{
		/* 取得web认证页面URL、用户请求的web网页的URL */
		if (!rt_skb_create_webauth_url(skb, auth_url, iph->saddr, eth->h_source, ni->ni_vap))
		{	
			printk(KERN_DEBUG"%s-%d: create webauth url failed!\n",__FUNCTION__, __LINE__);
			return RX_DROP_UNUSABLE;
		}

		httph = rt_skb_get_httph(tcph, tcph->doff << 2, iph->ihl << 2,skb->len);
		if (!httph || !get_original_web_url(httph,dom_name,path))
		{
			return RX_DROP_UNUSABLE;	
		}

		memset(httphdr, 0, sizeof(httphdr));
		if(rt_skb_create_httphdr(httphdr, auth_url, path, dom_name))
		{	
			printk(KERN_DEBUG"%s-%d: create http header failed!\n",__FUNCTION__, __LINE__);
			return RX_DROP_UNUSABLE;
		}

		rt_skb_create(skb, ni->ni_vap, iph, tcph, httphdr);

		return RX_DROP_UNUSABLE;
	}
	else if (ret == 0)
	{
		return RX_DROP_UNUSABLE;
	}
	else if (ret == -2) {
		rt_create_connect_skb(skb, ni->ni_vap, iph, tcph);
		return RX_DROP_UNUSABLE;
	}
	
	return RX_CONTINUE;
}

u8 rt_dhcp_parse_ostype(u8 *option)
{
	int option_value_len = 0;
	int i,j ,array_size,option_type;
	
	if(NULL == option)
	{
		return OS_NONE;
	}

	option_type = option[0];
	option_value_len = option[1];
	array_size = sizeof(dhcp_device_option);

	for(i = 0; i< array_size; i++)
	{
		if(dhcp_device_option[i].option_type == option_type)
		{
			if(option_value_len < dhcp_device_option[i].compare_len)
			{
				continue;
			}
			
			for(j = 0; j < dhcp_device_option[i].compare_len;j++)
			{
				if(dhcp_device_option[i].opion_value[j] != option[2+j])
				{
					break;
				}
			}

			if(j == dhcp_device_option[i].compare_len)
			{
				return dhcp_device_option[i].os_type;
			}
		}
	}

	return OS_NONE;
}


void rt_dhcp_parse_devname(u8 *option, struct ieee80211_node *ni)
{
	int i = 0;
	int option_value_len = 0;
	char client_name[IEEE80211_NODE_DEVNAME_MAX];
	
	if(!option || !ni)
	{
		return ;
	}

	option_value_len = option[1];
	if(option_value_len >= 128)
	{
		return ;
	}

	memset(client_name, 0, IEEE80211_NODE_DEVNAME_MAX);
	for(i = 0; i < option_value_len;i++)
	{
		sprintf(&client_name[i],"%c",(option+2)[i]);
	}

	client_name[i] = '\0';
	memcpy(ni->ni_devname, client_name, IEEE80211_NODE_DEVNAME_MAX);

}

u8 rt_dhcp_parse_message_type(u8 *option)
{
	int option_value_len = 0;
    
	if(!option)
	{
		return 0;
	}

	option_value_len = option[1];
	if(option_value_len > 1)
	{
		return 0;
	}

    return option[2];
}

void rt_dhcp_parse_options(struct dhcphdr *dhcph, struct ieee80211_node *ni)
{
	int i = 0, option_len = 0;
	u8 *optionptr = NULL;
	int over = 0, done = 0, curr = OPTION_FIELD;
	u8 *current_option = NULL;
	u8 msg_type = 0;
    
	if (dhcph == NULL)
	{
		return ;
	}

	optionptr = &(dhcph->exten[4]);//pre 4 bytes is cokie
	i = 0;
	option_len = 308;
	
	while (!done) 
	{
		if (i >= option_len) 
		{
			return ;
		}
		
		switch (optionptr[i + OPT_CODE]) 
		{
            case DHCP_MESSAGE_TYPE:
				if (i + 1 + optionptr[i + OPT_LEN] >= option_len) 
				{
					return ;
				}
     
				current_option = &(optionptr[i + OPT_CODE]);
				msg_type = rt_dhcp_parse_message_type(current_option);
                if (DHCPREQUEST == msg_type)
                {
                    ni->ni_ath_flags |= IEEE80211_NODE_DHCP_BEGIN;
                }
                
				i += optionptr[OPT_LEN + i] + 2;/*option value length + type(1) + len(1)*/
				break;
                
			case DHCP_PARAM_REQ:
			case DHCP_VENDOR:
				if (i + 1 + optionptr[i + OPT_LEN] >= option_len) 
				{
					return ;
				}
     
				current_option = &(optionptr[i + OPT_CODE]);
				ni->ni_ostype = rt_dhcp_parse_ostype(current_option);
				i += optionptr[OPT_LEN + i] + 2;/*option value length + type(1) + len(1)*/
				break;

			case DHCP_HOST_NAME:
				if (i + 1 + optionptr[i + OPT_LEN] >= option_len) 
				{
					return ;
				}

				current_option = &(optionptr[i + OPT_CODE]);
				rt_dhcp_parse_devname(current_option, ni);
				i += optionptr[OPT_LEN + i] + 2;/*option value length + type(1) + len(1)*/
				break;
				
			case DHCP_PADDING:
				i++;
				break;
				
			case DHCP_OPTION_OVER:
				if (i + 1 + optionptr[i + OPT_LEN] >= option_len) 
				{
					return ;
				}
				over = optionptr[i + 3];
				i += optionptr[OPT_LEN] + 2;
				break;
				
			case DHCP_END:
				if (curr == OPTION_FIELD && over & FILE_FIELD) 
				{
					optionptr = dhcph->boot_file;
					i = 0;
					option_len = 128;
					curr = FILE_FIELD;
				} 
				else if (curr == FILE_FIELD && over & SNAME_FIELD) 
				{
					optionptr = dhcph->serv_name;
					i = 0;
					option_len = 64;
					curr = SNAME_FIELD;
				} 
				else 
				{
					done = 1;
				}
				
				break;
				
			default:
				i += optionptr[OPT_LEN + i] + 2;
		}
	}

	return ;
}



void rt_dhcp_parse_skb(struct sk_buff *skb, struct udphdr *udph, struct ieee80211_node *ni)
{
	struct dhcphdr *dhcph = NULL;
	
	dhcph = (struct dhcphdr *)((u8 *)udph + sizeof(struct udphdr));

	if (BOOTREQUEST == dhcph->op)
	{
		rt_dhcp_parse_options(dhcph, ni);
	}

    return;
}

int rt_udp_parser(struct sk_buff *skb, 
						struct iphdr *iph, 
						struct udphdr *udph, 
						struct ieee80211_node *ni)
{
	if(!skb || !iph || !udph || !ni)
		return RX_DROP_UNUSABLE;
	
	switch(udph->dest)
	{
		case UDP_DHCP_SERVER_PORT:
			if(!(ni->ni_ath_flags & IEEE80211_NODE_DHCP_BEGIN))
			{
				rt_dhcp_parse_skb(skb, udph, ni);
			}

			return RX_CONTINUE;
		case UDP_DNS_PORT:
			return RX_CONTINUE;
		default:
			break;
	}

	return RX_DROP_UNUSABLE;
}

int rt_skb_allow_pass(struct ieee80211vap  *vap, u32 addr)
{
    struct list_head *pos = NULL;
    struct ip_address_obj *ip_entry = NULL;

    if (!vap)
        return 0;
    
    if (list_empty(&vap->iv_white_ip_list))
        return 0;

    list_for_each(pos, &vap->iv_white_ip_list)
    {
        ip_entry = list_entry(pos, struct ip_address_obj, list);
        if(!ip_entry)
            continue;

        if ((WHITE_IP_HOST == ip_entry->type) && 
            (ip_entry->data.ip_host.ip_addr == addr))
        {
            return 1;
        }
        else if ((WHITE_IP_RANGE == ip_entry->type) && 
            (ip_entry->data.ip_range.ip_begin <= addr) &&
            (addr <= ip_entry->data.ip_range.ip_end))
        {
            return 1;
        }
        else if ((WHITE_IP_MASK == ip_entry->type) &&
            (ip_entry->data.ip_mask.ip_addr & ip_entry->data.ip_mask.ip_mask) == (addr & ip_entry->data.ip_mask.ip_mask))
        {
            return 1;
        }
    }

    return 0;
}

int rt_tcp_parser(struct sk_buff *skb, 
						struct iphdr *iph, 
						struct tcphdr *tcph, 
						struct ieee80211_node *ni)
{
    struct ieee80211vap     *vap = NULL;

	if(!ni)
		return RX_DROP_UNUSABLE;

	vap = ni->ni_vap;
	if(rt_skb_allow_pass(vap, iph->daddr))
		return RX_CONTINUE;

	switch(tcph->dest)
	{
		case TCP_HTTP_PORT:
			if((vap->iv_portal_enable) && !(ni->ni_ath_flags & IEEE80211_NODE_PORTAL_DONE))
			{
                ni->ni_ath_flags |= IEEE80211_NODE_IP_ERROR;
				return rt_skb_webauth_redirect(skb, ni);
			}
		case TCP_DNS_PORT:
			return RX_CONTINUE;
		default:
			break;
	}

	return RX_DROP_UNUSABLE;
}

int rt_skb_parser(struct sk_buff *skb, struct ieee80211_node *ni)
{
	u8 ret = RX_CONTINUE;
	struct ethhdr *eth = NULL; 
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;

	if(!skb || !ni)
		return RX_DROP_UNUSABLE;

	eth = eth_hdr(skb);
	if(!eth)
	{
		return RX_DROP_UNUSABLE;
	}

	switch(eth->h_proto)
	{
		case ETH_P_IP:
			iph = (struct iphdr *)((u8 *)eth+sizeof(struct ethhdr));
			if ((iph->saddr) && (iph->saddr != ni->ni_haddr) && !IEEE80211_ADDR_EQ(ni->ni_vap->iv_myaddr, ni->ni_macaddr))
			{
				ni->ni_haddr = iph->saddr;
				ni->ni_ath_flags |= IEEE80211_NODE_DHCP_DONE;
				rt_assoc_notify(ni->ni_vap, ni->ni_macaddr, RT_ACTION_ADD_NOTIFY);
			}
			
			switch(iph->protocol)
			{
				case IPPROTO_UDP:
					udph = (struct udphdr *)((u8 *)iph + (iph->ihl * 4));
					ret = rt_udp_parser(skb, iph, udph, ni);
					break;
				case IPPROTO_TCP:
                    
					tcph = (struct tcphdr *)((u8 *)iph + (iph->ihl * 4));
					ret = rt_tcp_parser(skb, iph, tcph, ni);
					break;
				default:
					ret = RX_DROP_UNUSABLE;
					break;
			}
			
			break;
		
		default:
			break;
	}

	return ret;
}

