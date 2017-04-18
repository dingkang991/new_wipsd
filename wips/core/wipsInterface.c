#include "wipsInterface.h"
#include "memory.h"
#include "main.h"


void wipsd_handle_wlansniffrm(__u8 *buf, int len,core2EventLib_t* core2EventLib)
{
	int headOffset = 0;
	int ret = 0;
	
	wNode_t* nodeInfo = core2EventLib->wNode;
	snprintf(core2EventLib->tmpInfo,128,"get info from core,buf:%p,len:%d,buf:%s\n",buf,len,buf);
	if(buf == NULL || len == 0 || core2EventLib == NULL)
	{
		log_error("parems error\n");
		return ;
	}

    memset((void *)nodeInfo->proberInfo.proberMac, 0, sizeof(ETH_ALEN));
    memcpy((void *)nodeInfo->proberInfo.proberMac,buf+(len-ETH_ALEN),ETH_ALEN);
	len -= 6;

	
	if(wipsd_ieee80211_packet_prism(buf, &headOffset)) {
		if(headOffset > len){
			log_error("Invalid prism header packet!\t\n");
			return 1;
		}

		ret = wipsd_ieee80211_prism_parse(buf, nodeInfo);
		if(!ret){
			log_error("Parse radiotap failed!\t\n");
			return 1;
		}
	}else if(wipsd_ieee80211_packet_radiotap(buf, &headOffset)){
		if(headOffset > len){
			log_error("Invalid radiotap header packet!\t\n");
			return 1;
		}
		ret = wipsd_ieee80211_radiotap_parse(buf, len, nodeInfo);
		if(ret){
			log_error("Parse radiotap failed!\t\n");
			return 1;
		}
	}else {
		log_error("Invalid 802.11 packet!\t\n");
		return 1;
	}
	
	

	handleAllCB(&ctx.pBeaconList,core2EventLib);
	

}


void wipsd_handle_packet(struct uloop_fd *fd, unsigned int events)
{
	int bytes = 0;
	int err = 0;
	__u8 buf[WIPS_PKT_MAX_LEN];
	struct sockaddr_in addr;
	int addrLen = sizeof(struct sockaddr_in);
	INIT_CORE2EVENTLIB_TMP(pBeacon);
	initWnode(pBeacon.wNode);
	pBeacon.wNode->proberInfo.fd = fd;
	
	memset((void *)buf, 0, sizeof(buf));
	
	do {
		errno = 0;
		bytes = recvfrom(fd->fd, buf, sizeof(buf), 0, (struct sockaddr *)&pBeacon.wNode->proberInfo.addr, &addrLen);
		if (bytes < 0){
			log_error("Recv packet failed(%d) error:%d!\t\n",bytes,errno);
			goto OUT;
		}

		err = errno;
		if (err == EAGAIN || err == EINTR) {
			log_info("eagain or eintr happened!\t\n");
			continue;
		} else {
			break;
		}
	}while(err == EINTR);
	ctx.packetCounter++;

	wipsd_handle_wlansniffrm(buf, bytes, &pBeacon);
	OUT:
//		log_info("goto out! count:%d\t\n",ctx.packetCounter);
		DESTROY_CORE2EVENTLIB(pBeacon)
		uloop_fd_add(fd, ULOOP_READ);

	return;
}


int wipsInitSocket(wipsInterface_t *wipsIf)
{
	if(NULL == wipsIf)
		return -1;

	wipsIf->fd = wipsIf->uloopFd.fd= usock(USOCK_UDP |USOCK_SERVER |USOCK_IPV4ONLY,wipsIf->ip,wipsIf->port);
	if(wipsIf->fd >= 0)
	{
		log_error("listen [%s : %s] usock success\n",wipsIf->ip,wipsIf->port);
		wipsIf->uloopFd.cb = wipsd_handle_packet;
		uloop_fd_add(&wipsIf->uloopFd, ULOOP_READ);
		return 0;
	}
	
	log_error("listen [%s : %s] usock fail:%d \n",wipsIf->ip,wipsIf->port,errno);
	return -1;
}

wipsInterface_t* initWipsInterface(wipsInterface_t* wipsInterface)
{
	wipsInterface_t* tmp;
	tmp = wipsInterface?wipsInterface:MM_MALLOC(CORE_ID,sizeof(wipsInterface_t));
	if(tmp == NULL)
	{
		log_error("MM_MALLOC error\n");
		return NULL;
	}
	memset(tmp,0,sizeof(wipsInterface_t));
	return tmp;
}

wipsInterface_t* setWipsInterface(wipsInterface_t* wipsInterface)
{
	wipsInterface_t* tmp = initWipsInterface(wipsInterface);
	/*
	tmp->ip = "0.0.0.0";
	tmp->port = #WIPSD_SOCKET_PORT;
	*/
	snprintf(tmp->ip,32,"0.0.0.0");
	snprintf(tmp->port,8,"%s",WIPSD_SOCKET_PORT_STR);
	return tmp;
}



