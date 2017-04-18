#ifndef RT_INFO_H__
#define RT_INFO_H__

#define UDP_DHCP_SERVER_PORT    67
#define UDP_DHCP_CLIENT_PORT    68
#define	UDP_DNS_PORT			53
#define TCP_HTTP_PORT			80
#define	TCP_DNS_PORT			53

#define BOOTREQUEST     1
#define BOOTREPLY       2

#define DHCPDISCOVER	1
#define DHCPOFFER		2
#define DHCPREQUEST		3
#define DHCPDECLINE		4
#define DHCPACK			5
#define DHCPNAK			6
#define DHCPRELEASE		7
#define DHCPINFORM		8

#define OPTION_FIELD		0
#define FILE_FIELD		1
#define SNAME_FIELD		2

/* miscellaneous defines */
#define MAC_BCAST_ADDR		(u8 *) "\xff\xff\xff\xff\xff\xff"
#define MAC_ZERO_ADDR		(u8 *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" /* chaddr of lease, 16 bits */
#define OPT_CODE 		0
#define OPT_LEN 		1
#define OPT_DATA 		2

/* DHCP option codes (partial list) */
#define DHCP_PADDING		0x00
#define DHCP_SUBNET_MASK	0x01
#define DHCP_TIME_OFFSET	0x02
#define DHCP_ROUTER		0x03
#define DHCP_TIME_SERVER	0x04
#define DHCP_NAME_SERVER	0x05
#define DHCP_DNS_SERVER		0x06
#define DHCP_LOG_SERVER		0x07
#define DHCP_COOKIE_SERVER	0x08
#define DHCP_LPR_SERVER		0x09
#define DHCP_HOST_NAME		0x0c
#define DHCP_BOOT_SIZE		0x0d
#define DHCP_DOMAIN_NAME	0x0f
#define DHCP_SWAP_SERVER	0x10
#define DHCP_ROOT_PATH		0x11
#define DHCP_IP_TTL		0x17
#define DHCP_MTU		0x1a
#define DHCP_BROADCAST		0x1c
#define DHCP_NTP_SERVER		0x2a
#define DHCP_WINS_SERVER	0x2c
#define DHCP_REQUESTED_IP	0x32
#define DHCP_LEASE_TIME		0x33
#define DHCP_OPTION_OVER	0x34
#define DHCP_MESSAGE_TYPE	0x35
#define DHCP_SERVER_ID		0x36
#define DHCP_PARAM_REQ		0x37
#define DHCP_MESSAGE		0x38
#define DHCP_MAX_SIZE		0x39
#define DHCP_T1			0x3a
#define DHCP_T2			0x3b
#define DHCP_VENDOR		0x3c
#define DHCP_CLIENT_ID		0x3d
#define DHCP_FQDN		0x51

#define DHCP_END		0xFF

enum ath_rx_result
{
	RX_CONTINUE,
	RX_DROP_UNUSABLE
};

struct dhcphdr {		
	u8 op;			/* 1=request, 2=reply */
	u8 htype;		/* HW address type */
	u8 hlen;		/* HW address length */
	u8 hops;		/* Used only by gateways */
	__be32 xid;		/* Transaction ID */
	__be16 secs;		/* Seconds since we started */
	__be16 flags;		/* Just what it says */
	__be32 client_ip;		/* Client's IP address if known */
	__be32 your_ip;		/* Assigned IP address */
	__be32 server_ip;		/* (Next, e.g. NFS) Server's IP address */
	__be32 relay_ip;		/* IP address of BOOTP relay */
	u8 hw_addr[16];		/* Client's HW address */
	u8 serv_name[64];	/* Server host name */
	u8 boot_file[128];	/* Name of boot file */
	u8 exten[312];		/* DHCP options / BOOTP vendor extensions */
};


struct dhcp_device_option_t
{
	enum ieee80211_node_ostype os_type;
	char device[64];
	u16 option_type;
	u8 opion_value[64];
	u8 compare_len;
};

#define NMACQUAD(addr) \
	((unsigned char *)addr)[0], \
	((unsigned char *)addr)[1], \
	((unsigned char *)addr)[2], \
	((unsigned char *)addr)[3], \
	((unsigned char *)addr)[4], \
	((unsigned char *)addr)[5]

#define NMACQUAD_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

int rt_skb_parser(struct sk_buff *skb, struct ieee80211_node *ni);
//void rt_dhcp_options_prase(struct dhcphdr *dhcph, struct ieee80211_node *ni);
//int is_http_get(struct tcphdr *tcph,unsigned int tcph_len,unsigned int iph_len,unsigned int skb_len);
//inline char * get_http_head_addr(struct tcphdr *tcph,unsigned int tcph_len,unsigned int iph_len,unsigned int skb_len);
//unsigned int rt_get_auth_url(char * auth_url);
//unsigned int get_original_web_url(const char *httphdr,char * domain_name, char * web_page_path);
//unsigned int creat_http_head(char * RdHeadMsg,const char *auth_url,const char *path,const char *dom_name);
//int rt_web_redirect(struct sk_buff *srcsk, const struct net_device *out,char * rd_url);

#if 0
unsigned short int rt_csum_tcpudp_magic(unsigned long saddr,
											   unsigned long daddr,
											   unsigned short len,
											   unsigned short proto,
											   unsigned int sum);
#endif											   
#endif


