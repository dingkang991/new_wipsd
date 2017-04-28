#include "wipsInterface.h"
#include "memory.h"
#include "main.h"


void wipsd_handle_wlansniffrm(__u8 *buf, int len,core2EventLib_t* core2EventLib)
{
	int headOffset = 0;
	int ret = 0;
    int type = -1, subtype, dir;
    u_int8_t* bssid=NULL;
    u_ini8_t* sta=NULL;
	struct ieee80211_frame *wh;
	wNode_t* wNodeTmp=NULL;
	
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
			return ;
		}

		ret = wipsd_ieee80211_prism_parse(buf, nodeInfo);
		if(!ret){
			log_error("Parse radiotap failed!\t\n");
			return ;
		}
	}else if(wipsd_ieee80211_packet_radiotap(buf, &headOffset)){
		if(headOffset > len){
			log_error("Invalid radiotap header packet!\t\n");
			return ;
		}
		ret = wipsd_ieee80211_radiotap_parse(buf, len, nodeInfo);
		if(ret){
			log_error("Parse radiotap failed!\t\n");
			return ;
		}
	}else {
		log_error("Invalid 802.11 packet!\t\n");
		return ;
	}
	
	core2EventLib->wh = wh = (struct ieee80211_frame*) (buf+headOffset);
	core2EventLib->whLen = len - headOffset;
    if (unlikely((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) != IEEE80211_FC0_VERSION_0)) {
        /* XXX: no stats for it. */
        return ;
    }
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

    
	switch (type)
	{
		case IEEE80211_FC0_TYPE_DATA:
		
		log_info("IEEE80211_FC0_TYPE_DATA:\n");
			switch(dir)
			{
				case IEEE80211_FC1_DIR_TODS:
					bssid = wh->i_addr1;
					sta = wh->i_addr2;
					break;
				case IEEE80211_FC1_DIR_FROMDS:
					bssid = wh->i_addr2;
					sta = wh->iaddr1;
					break;
				case IEEE80211_FC1_DIR_NODS:
					bssid = wh->i_addr1;
					sta = wh->iaddr_2;
					break;
				case IEEE80211_FC1_DIR_DSTODS:
					bssid = wh->i_addr1;
					sta = wh->iaddr_2;
					break;
				default:
					log_error("can not parse DIR in data frame\n");
					return;
					break;
			}
			wNodeTmp = (wNode_t*)hash_find(ctx.wNodeAllHash, (const char *)bssid, ETH_ALEN);
			if(wNodeTmp != NULL){
				core2EventLib->wNodeBssid = wNodeTmp;
			}
			
			wNodeTmp = (wNode_t*)hash_find(ctx.wNodeAllHash, (const char*)sta,ETH_ALEN);
			if(wNodeTmp != NULL){
				core2EventLib->wNodeSta = wNodeTmp;
			}
			
			handleAllCB(&ctx.pDataList,core2EventLib);
			break;
		case IEEE80211_FC0_TYPE_CTL:
			log_info("WLAN_FC_TYPE_MGMT:\n");
			switch(subtype){
				case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
					log_info("WLAN_FC02_STYPE_ASSOC_REQ:\n");
					bssid = wh->i_addr3;
					sta = wh->i_addr2;
					handleAllCB(&ctx.pAssocationRequestList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
					log_info("WLAN_FC02_STYPE_ASSOC_RESP:\n");
					sta = wh->i_addr1;
					bssid = wh->i_addr3;
					handleAllCB(&ctx.pAssocationResponseList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
					log_info("WLAN_FC02_STYPE_REASSOC_REQ:\n");
					sta = wh->i_addr2;
					bssid = wh->i_addr3;
					handleAllCB(&ctx.pReassocationRequestList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
					log_info("WLAN_FC02_STYPE_REASSOC_RESP:\n");
					sta = wh->i_addr1;
					bssid = wh->iaddr3;
					handleAllCB(&ctx.pReassocationResponseList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
					log_info("WLAN_FC02_STYPE_PROBE_REQ:\n");
					sta = wh->i_addr2;
					bssid = NULL;
					handleAllCB(&ctx.pProbeRequestList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
					log_info("IEEE80211_FC0_SUBTYPE_PROBE_RESP");
					sta = wh->i_addr1;
					bssid = wh->i_addr2;
					handleAllCB(&ctx.pProbeResponseList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_BEACON:
					log_info("WLAN_FC02_STYPE_BEACON:\n");
					sta = NULL;
					bssid = wh->i_addr3;
					handleAllCB(&ctx.pBeaconList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_ATIM:
				//	handleAllCB(&ctx.pATIMList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_DISASSOC:
					bssid = wh->i_addr3;
					handleAllCB(&ctx.pDisassociationList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_AUTH:
					handleAllCB(&ctx.pAuthenticationList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_DEAUTH:
					handleAllCB(&ctx.pDeauthenicationList,core2EventLib);
					break;
				default :
					break;
			}
			break;
		case IEEE80211_FC0_TYPE_MGT:
			log_info("WLAN_FC_TYPE_CTRL:\n");
			switch (fc02){
				case WLAN_FC_STYPE_PSPOLL:
					//show_hdr_pspoll(frm);
					//WIPSD_DEBUG("WLAN_FC_STYPE_PSPOLL:\n");
					break;
				case WLAN_FC_STYPE_RTS:
					//show_hdr_rts(frm);
					//WIPSD_DEBUG("WLAN_FC_STYPE_RTS:\n");
					check_rts(buf, len, &sta_val);
					break;
				case WLAN_FC_STYPE_CFEND:
				case WLAN_FC_STYPE_CFENDACK:
					//WIPSD_DEBUG("WLAN_FC_STYPE_CFEND WLAN_FC_STYPE_CFENDACK:\n");
					//show_hdr_cfend(frm);
					break;
				case WLAN_FC_STYPE_CTS:
					//WIPSD_DEBUG("WLAN_FC_STYPE_CTS:\n");
					check_cts(buf, len, &sta_val);
					break;
				case WLAN_FC_STYPE_ACK:
					//WIPSD_DEBUG("WLAN_FC_STYPE_ACK:\n");
					//show_hdr_cts(frm);
					check_ack(buf, len, &sta_val);
					break;
				default :
					break;
			}
			break;
		default :
			break;
	}


    wNodeTmp = (wNode_t*)hash_find(ctx.wNodeAllHash, (const char *)&wnode->mac, 6)
    
    
	
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



