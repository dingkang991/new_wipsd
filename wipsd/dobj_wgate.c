#include "hash.h"
#include "zthread_support.h"
#include "dobj_wgate.h"

#include "debug.h"

static struct hash_control* __wgate_table__ = NULL;
int dobj_wgate_init(void)
{
	if( __wgate_table__!=NULL )
		return -1;
	__wgate_table__	=	hash_new();
	return 0;
}
#if 0
static void destroy (char *string, char *value)
{
	free (string);
	free (value);
}
int dobj_wgate_destroy(void)
{
	hash_traverse(__wgate_table__, (void(*)(const char*, void*))destroy);
	hash_die(__wgate_table__);

	return 0;
}



#define PRINT_MAC(mac) WIPSD_DEBUG("mac %02x:%02x:%02x:%02x:%02x:%02x\t", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
#define PRINT_IP(ip) WIPSD_DEBUG("ip %d.%d.%d.%d\t", ip[0], ip[1], ip[2], ip[3])

int dobj_wgate_update(__u8* mac, __u8* ip)
{
	__u8* dip;

#ifdef DEBUG_WIPSD
	WIPSD_DEBUG("wgate to insert:");
	PRINT_MAC(mac);
	PRINT_IP(ip);
	WIPSD_DEBUG("\n");
#endif

	dip = hash_find(__wgate_table__, (char *)mac, 6);
	if(dip==NULL){
		__u8* dmac;
		dmac = malloc(6);
		dip = malloc(4);
		if(dmac==NULL||dip==NULL){
			free(dmac);
			free(dip);
			return -1;
		}
		memcpy(dmac, mac, 6);
		memcpy(dip, ip, 4);
		if(hash_insert(__wgate_table__, (char *)dmac, 6, dip)!=NULL ){
			free(dmac);
			free(dip);
			return -1;
		}
		return 1;
	}else{
		memcpy(dip, ip, 4);
		return 0;
	}
}
#endif
int dobj_wgate_query(__u8* mac, __u8* ip)
{
	__u8* sip;
	sip = hash_find(__wgate_table__, (char *)mac, 6);
	if(sip==NULL){
		return -1;
	}
	memcpy(ip, sip, 4);
	return 0;
}
