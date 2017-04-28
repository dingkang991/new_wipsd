#include "wipsInterface.h"
#include "memory.h"
#include "main.h"
#include "ieee80211.h"
const u_int8_t	  addrBcast[IEEE80211_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};

void syncBssidAndStaInfo(core2EventLib_t* core2EventLib)
{
	if(core2EventLib->wNodeSta != NULL)
	{
		memcpy(&core2EventLib->wNodeSta->proberInfo,&core2EventLib->proberInfo,sizeof(proberInfo_t));
		memcpy(&core2EventLib->wNodeSta->radioInfo,&core2EventLib->radioInfo,sizeof(radioInfo_t));
		setTimeNow(&core2EventLib->wNodeSta->lastTime);
		core2EventLib->wNodeSta->initFlag = 0;
	}

	if(core2EventLib->wNodeBssid != NULL)
	{
		memcpy(&core2EventLib->wNodeBssid->proberInfo,&core2EventLib->proberInfo,sizeof(proberInfo_t));
		memcpy(&core2EventLib->wNodeBssid->radioInfo,&core2EventLib->radioInfo,sizeof(radioInfo_t));
		setTimeNow(&core2EventLib->wNodeBssid->lastTime);
		core2EventLib->wNodeBssid->initFlag = 0;
	}
	
}
void findBssidAndSta(core2EventLib_t* core2EventLib,u_int8_t* bssid,u_int8_t* sta)
{
	wNode_t* wNodeTmp=NULL;

	if(core2EventLib == NULL)
	{
		log_error("parms is NULL\n");
		return;
	}

	if(bssid == NULL || IEEE80211_ADDR_EQ(addrBcast,bssid))
	{
		core2EventLib->wNodeBssid = NULL;
	}else{
		wNodeTmp = (wNode_t*)hash_find(ctx.wNodeAllHash, (const char *)bssid, ETH_ALEN);
		if(wNodeTmp != NULL){
			core2EventLib->wNodeBssid = wNodeTmp;
		}else{
			core2EventLib->wNodeBssid = initWnode(NULL);
			memcpy(core2EventLib->wNodeBssid->mac,bssid,ETH_ALEN);
			hash_insert(ctx.wNodeAllHash,(const char*)core2EventLib->wNodeBssid->mac,ETH_ALEN,(void*)core2EventLib->wNodeBssid);
		}
	}
	
	if(sta == NULL || IEEE80211_ADDR_EQ(addrBcast,sta))
	{
		core2EventLib->wNodeBssid = NULL;
	}else{
		wNodeTmp = (wNode_t*)hash_find(ctx.wNodeAllHash, (const char*)sta,ETH_ALEN);
		if(wNodeTmp != NULL){
			core2EventLib->wNodeSta = wNodeTmp;
		}else{
			core2EventLib->wNodeSta = initWnode(NULL);
			memcpy(core2EventLib->wNodeBssid->mac,sta,ETH_ALEN);
			hash_insert(ctx.wNodeAllHash,(const char*)core2EventLib->wNodeSta->mac,ETH_ALEN,(void*)core2EventLib->wNodeSta);
		}
	}
}
void bssidAndStaMacParse(struct ieee80211_frame *wh ,u_int8_t** bssid,u_int8_t** sta)
{
//	const u_int8_t    addrBcast[IEEE80211_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};
	
	if(wh == NULL || bssid == NULL || sta == NULL)
	{
		log_error("parm is NULL\n");
		return ;
	}

	

	if(IEEE80211_ADDR_EQ(wh->i_addr1,addrBcast) && IEEE80211_ADDR_EQ(wh->i_addr2,addrBcast))
	{
		*bssid = wh->i_addr3;
		*sta = NULL;
		return ;
	}
	if(IEEE80211_ADDR_EQ(wh->i_addr3,addrBcast))
	{
		*bssid = NULL;
		if(IEEE80211_ADDR_EQ(wh->i_addr1,addrBcast))
		{
			*sta = wh->i_addr2;
		}else{
			*sta = wh->i_addr1;
		}
		return;
	}

	*bssid = wh->i_addr3;
	if(IEEE80211_ADDR_EQ(wh->i_addr1,*bssid))
	{
		*sta = wh->i_addr2;
	}else{
		*sta = wh->i_addr1;
	}

	return ;
}

void wipsd_handle_wlansniffrm(__u8 *buf, int len,core2EventLib_t* core2EventLib)
{
	int headOffset = 0;
	int ret = 0;
    int type = -1, subtype, dir;
    u_int8_t* bssid=NULL;
    u_int8_t* sta=NULL;
	struct ieee80211_frame *wh;
	wNode_t* wNodeTmp=NULL;
	
	proberInfo_t* proberInfo = &core2EventLib->proberInfo;
	radioInfo_t* radioInfo = &core2EventLib->radioInfo;
	
	snprintf(core2EventLib->tmpInfo,128,"get info from core,buf:%p,len:%d,buf:%s\n",buf,len,buf);
	if(buf == NULL || len == 0 || core2EventLib == NULL)
	{
		log_error("parems error\n");
		return ;
	}

    memset((void *)proberInfo->proberMac, 0, sizeof(ETH_ALEN));
    memcpy((void *)proberInfo->proberMac,buf+(len-ETH_ALEN),ETH_ALEN);
	len -= 6;

	if(wipsd_ieee80211_packet_prism(buf, &headOffset)) {
		if(headOffset > len){
			log_error("Invalid prism header packet!\t\n");
			return ;
		}

		ret = wipsd_ieee80211_prism_parse(buf, radioInfo);
		if(!ret){
			log_error("Parse radiotap failed!\t\n");
			return ;
		}
	}else if(wipsd_ieee80211_packet_radiotap(buf, &headOffset)){
		if(headOffset > len){
			log_error("Invalid radiotap header packet!\t\n");
			return ;
		}
		ret = wipsd_ieee80211_radiotap_parse(buf, len, radioInfo);
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
    if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) != IEEE80211_FC0_VERSION_0) {
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
					sta = wh->i_addr1;
					break;
				case IEEE80211_FC1_DIR_NODS:
					bssid = wh->i_addr1;
					sta = wh->i_addr2;
					break;
				case IEEE80211_FC1_DIR_DSTODS:
					bssid = wh->i_addr1;
					sta = wh->i_addr2;
					break;
				default:
					log_error("can not parse DIR in data frame\n");
					return;
					break;
			}
			findBssidAndSta(core2EventLib,bssid,sta);
			handleAllCB(&ctx.pDataList,core2EventLib);
			break;
		case IEEE80211_FC0_TYPE_MGT:
			log_info("WLAN_FC_TYPE_MGMT:\n");
			bssidAndStaMacParse(wh,&bssid,&sta);
			findBssidAndSta(core2EventLib,bssid,sta);
			handleAllCB(&ctx.pAllManageMentFrameList,core2EventLib);
			switch(subtype){
				case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
					log_info("WLAN_FC02_STYPE_ASSOC_REQ:\n");
					handleAllCB(&ctx.pAssocationRequestList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
					log_info("WLAN_FC02_STYPE_ASSOC_RESP:\n");
					handleAllCB(&ctx.pAssocationResponseList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
					log_info("WLAN_FC02_STYPE_REASSOC_REQ:\n");
					handleAllCB(&ctx.pReassocationRequestList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
					log_info("WLAN_FC02_STYPE_REASSOC_RESP:\n");
					handleAllCB(&ctx.pReassocationResponseList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
					log_info("WLAN_FC02_STYPE_PROBE_REQ:\n");
					handleAllCB(&ctx.pProbeRequestList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
					handleAllCB(&ctx.pProbeResponseList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_BEACON:
					log_info("WLAN_FC02_STYPE_BEACON:\n");
					handleAllCB(&ctx.pBeaconList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_ATIM:
					log_info("IEEE80211_FC0_SUBTYPE_ATIM:\n");
					handleAllCB(&ctx.pATIMList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_DISASSOC:
					log_info("IEEE80211_FC0_SUBTYPE_DISASSOC:\n");
					handleAllCB(&ctx.pDisassociationList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_AUTH:
					log_info("IEEE80211_FC0_SUBTYPE_AUTH:\n");
					handleAllCB(&ctx.pAuthenticationList,core2EventLib);
					break;
				case IEEE80211_FC0_SUBTYPE_DEAUTH:
					log_info("IEEE80211_FC0_SUBTYPE_DEAUTH:\n");
					handleAllCB(&ctx.pDeauthenicationList,core2EventLib);
					break;
				default :
					break;
			}
			break;
		case IEEE80211_FC0_TYPE_CTL:
			log_info("WLAN_FC_TYPE_CTRL:\n");
			log_info("can not support just now\n");
			return ;/*
			switch (subtype){
				default :
					break;
			}
			break;*/
		default :
			break;
	}    
    
	syncBssidAndStaInfo(core2EventLib);
	return ;

}


void wipsd_handle_packet(struct uloop_fd *fd, unsigned int events)
{
	int bytes = 0;
	int err = 0;
	__u8 buf[WIPS_PKT_MAX_LEN];
	struct sockaddr_in addr;
	int addrLen = sizeof(struct sockaddr_in);
	core2EventLib_t info2Event;
	//INIT_CORE2EVENTLIB_TMP(pBeacon);
	memset(&info2Event,0,sizeof(core2EventLib_t));
	info2Event.wNodeSta = NULL;
	info2Event.wNodeBssid = NULL;
	info2Event.proberInfo.fd = fd;
	
	memset((void *)buf, 0, sizeof(buf));
	
	do {
		errno = 0;
		bytes = recvfrom(fd->fd, buf, sizeof(buf), 0, (struct sockaddr *)&info2Event.proberInfo.addr, &addrLen);
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
	freshTime();
	wipsd_handle_wlansniffrm(buf, bytes, &info2Event);
	OUT:
//		log_info("goto out! count:%d\t\n",ctx.packetCounter);
//		DESTROY_CORE2EVENTLIB(pBeacon)
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



