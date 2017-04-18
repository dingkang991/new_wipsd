#if 0
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
#include <linux/wireless.h>
#include "hash.h"
#include "ieee80211.h"
#include "wipsd_wnode.h"

#include "wipsd.h"
#include "ppclient.h"
#include "ms_cmd.h"
/*==========================================================*/
extern long fresh_time;
extern char * AC_ip;
extern int AC_port;
extern w_node_list * beacon_list_p;
extern w_node_list * beacon_list_tail;
extern w_node_list * sta_list_p;
extern w_node_list * sta_list_tail;

int ppclient_enable =0;
//socket data
int socketfd =-1;
#define ZERO_ID  0
#define REGISTER_ID  1
int cmd_intelid =100;
pptask * list_head =NULL;
__u8 * sendbuf =NULL;

/*==========================================================*/
#define DEFAULT_BUF_LEN 32
#define PROTOCOL_VERSION 1
#define IF_NAME "eth1"
static int get_local_mac(char * local_mac, char * pifname)
{
	int sockfd;
	struct ifreq struReq;
	sockfd = socket(PF_INET,SOCK_STREAM,0);
	memset(&struReq,0,sizeof(struReq));
	memset(local_mac,0,DEFAULT_BUF_LEN);

	strncpy(struReq.ifr_name, pifname, sizeof(struReq.ifr_name));
	ioctl(sockfd,SIOCGIFHWADDR,&struReq);
#if 0
	strncpy(local_mac, 
		ether_ntoa((const struct ether_addr *)struReq.ifr_hwaddr.sa_data), 
		DEFAULT_BUF_LEN);
#else
	is_mac_valid((unsigned char *)local_mac, struReq.ifr_hwaddr.sa_data);
#endif
	close(sockfd);
	return 0;
}

static int get_ap_name(char * ap_name, char * name)
{
	memset(ap_name,0,DEFAULT_BUF_LEN);

	strncpy(ap_name, name, DEFAULT_BUF_LEN);

	return 0;
}

static int get_ap_version(char * ap_version, char * name)
{
	memset(ap_version,0,DEFAULT_BUF_LEN);

	strncpy(ap_version, name, DEFAULT_BUF_LEN);

	return 0;
}

static pptask * malloc_pptask_node(ppdata * datap)
{//add new node
	pptask * newnode= NULL;
	newnode = malloc(sizeof(pptask));
	if(newnode == NULL){
		printf("malloc for new pptask node err!\n");
		return NULL;
	}
	memset(newnode,0,sizeof(pptask));
	newnode->cmd_id	 = datap->cmd_id;
	newnode->cmd_name   = datap->cmd_name;
	newnode->data	   = datap->data;

	return newnode;
}

//find the node by cmd_id or creat a node
static pptask * find_node_ppcmd(ppdata * datap, pptask ** head )
{
	pptask * p_oflist=NULL;
	pptask * p_oflist_tmp=NULL;

	if(*head == NULL){
		*head = malloc_pptask_node(datap);
		return *head;
	}

	p_oflist = *head;
	do{
		if(datap->cmd_id== p_oflist->cmd_id){
			return p_oflist;
		}
	}while(p_oflist->next);

	if((p_oflist_tmp = malloc_pptask_node(datap)) == NULL){
		return NULL;
	}
	p_oflist->next = p_oflist_tmp;
	p_oflist_tmp->last = p_oflist;
	return p_oflist_tmp;
}
#if 0
static void del_node_ppcmd( pptask * p_oflist, pptask ** head )
{
	pptask * p_tmp, * pp_tmp;

	if(p_oflist == NULL || *head == NULL) return;

	if( p_oflist == *head ){
		 pp_tmp = p_oflist->next;
		 *head = pp_tmp;
		 pp_tmp->last = NULL;
	}else if(p_oflist->next == NULL){
		p_tmp = p_oflist->last;
		p_tmp->next = NULL;
	}else{
		p_tmp = p_oflist->last;
		pp_tmp = p_oflist->next;
		p_tmp->next = pp_tmp;
		pp_tmp->last = p_tmp;
	}
	wipsd_free(p_oflist->data);
	wipsd_free(p_oflist);
}
#endif
int randx(void)
{
	srand((int)time(0));
	return(rand()%10+1);
}

int inet_connect(char *ip, int port)
{
	int fd = -1;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(struct sockaddr_in);

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket");
		return -2;
	}
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family	   = AF_INET;
	sa.sin_addr.s_addr  = inet_addr(ip);
	sa.sin_port	 = htons(port);
	if(connect(fd, (struct sockaddr *)&sa, sa_len) == 0){
		fprintf(stdout, "Connected to %s:%d fd[%d]\n", ip, port, fd);
#if 1
		if(send(fd, "Hello, I am connected!\n", 23, 0) == -1) {
			perror("send err");
		}
#endif
		return fd;
	}else{
		fprintf(stdout, "Connected to %s:%d failed, %s\n", ip, port, strerror(errno));
		close(fd);
		return -1;
	}
}

int create_connect(char *ip, int port)
{
	for(;;){
		socketfd = inet_connect(ip, port);
		if(socketfd > 0) break;
		sleep(randx());
	}
	return 0;
}

register_check * malloc_register_checkdata(void)
 {
	register_check * p_tmp = NULL;
	p_tmp = malloc(sizeof(register_check));
	if(p_tmp == NULL){
		printf("malloc_register_checkdata: malloc err!\n");
	}else{
		memset(p_tmp,0,sizeof(struct register_check));
	}
	return p_tmp;
 }
 
int scmd2ppcmdlist(int cmd, ppdata * datap)
#if 1
{return 0;}
#else
{
	struct list_tast *mp =NULL;
	ppdata * data =datap;

	if(!data){//internal call
		data = malloc(sizeof(ppdata));
		if(data == NULL){
			printf("scmd2ppcmdlist: malloc for new ppdata err!\n");
			return -1;
		}
		memset(data,0,sizeof(ppdata));
	}

	mp = malloc(sizeof(struct list_tast));
	if(mp == NULL){
		printf("scmd2ppcmdlist: malloc for new list_task err!\n");
		wipsd_free(data);
		return -1;
	}
	memset(mp,0,sizeof(struct list_tast));

	switch(cmd){
 		case REGISTER_REQ:{
			data->cmd_id = REGISTER_ID;//cmd_intelid++;
			data->cmd_name = REGISTER_REQ;
			data->sequence_type = 0;
			}
			break;

		case REGISTER_RESP:
			data->cmd_id = REGISTER_ID;//cmd_intelid++;
			data->cmd_name = REGISTER_RESP;
			data->sequence_type = 0;
			break;

		case KEEPALIVE_TO_SERVER:
			data->cmd_id = REGISTER_ID;//cmd_intelid++;
			data->cmd_name = KEEPALIVE_TO_SERVER;
			break;

		case KEEPALIVE_FROM_SERVER:
			data->cmd_id = REGISTER_ID;//cmd_intelid++;
			data->cmd_name = KEEPALIVE_FROM_SERVER;
			data->sequence_type = 0;
			break;
			
		case KEEPALIVE_CHECK:
			data->cmd_id = REGISTER_ID;//cmd_intelid++;
			data->cmd_name = KEEPALIVE_CHECK;
			data->sequence_type = KEEPALIVE_CHECK;
			break;

		case GET_APLIST:
			data->cmd_name = GET_APLIST;
			break;
			
		case GET_STALIST:
			data->cmd_name = GET_STALIST;
			break;
			
		case DEFAULT_CONFIG:
		case BLOCKING_CMD:
		case UNBLOCKING_CMD:
		case GET_BLOCKLIST:
		default :
			goto scmd2ppcmdlist_err;
			break;
	}

	mp->task_type= LIST_TASK_TCPAP2AC;
	mp->node = (void *)data;
	insertListTask(mp);

	return 0;
	
scmd2ppcmdlist_err:
	wipsd_free(data->data);
	wipsd_free(data);
	wipsd_free(mp);
	return -1;

}
#endif
int scmd_resolve(__u8 * buf, ppdata * data, int * len)
{
	struct cmd_req_head * head_req = (struct cmd_req_head * )buf;
	struct cmd_resp_head * head_resp = (struct cmd_resp_head * )buf;

	if(*len > head_req->data_len){
		*len -= head_req->data_len;
	}else{
		return -1;
	}

	switch(head_req->id){
		case W_DEV_REGISTER:{//resp
			register_check * p_tmp = NULL;
			p_tmp = malloc_register_checkdata();
			if(p_tmp == NULL){
				wipsd_free(data);
				printf("scmd_resolve: malloc for new register_check node err!\n");
				return -1;
			}
			p_tmp->register_ok = head_resp->success_flag;
			data->data = (void *)p_tmp;}
			break;
		case W_DEV_KEEPLIVE://resp
			break;
		case M_SERVER_SEND_CONFIG:
			break;
		case M_SERVER_SEND_POLICY:
			break;
		case M_SERVER_SEND_SOFT_V:
			break;
		case M_SERVER_SEND_W_DEV_INFO:
			break;

		case M_SERVER_SEND_BLOCK_CMD:
			break;
		case M_SERVER_SEND_DEBLOCK_CMD:
			break;

		case M_SERVER_GET_WLIST:
			break;
		case M_SERVER_GET_STATLIST:
			break;
		case M_SERVER_GET_BLKLIST:
			break;

		case M_SERVER_GET_EVENT_LOG:
			break;
		case M_SERVER_GET_NORMAL_LOG:
			break;
	}

	return head_req->id;

}

int recv_cmd(int fd)
{
	__u8 buf[8192];
	int len, len_tmp;
	ppdata * ppcmdata =NULL;

	len_tmp = len = recv(fd, buf, 8192, 0);

	if(len>0){
#ifndef DEBUG_XXX
		do{
			ppcmdata = malloc(sizeof(ppdata));
			if(ppcmdata == NULL){
				printf("recv_cmd: malloc for new ppdata err!\n");
				return -1;
			}
			memset(ppcmdata,0,sizeof(ppdata));
		switch(scmd_resolve( &buf[len_tmp - len], ppcmdata, &len)){
			case W_DEV_REGISTER:
#else
			if(strcmp((char *)buf,"Hello, register false!\n")==0)
#endif
				scmd2ppcmdlist(REGISTER_RESP, ppcmdata);
#ifndef DEBUG_XXX
				break;
			case W_DEV_KEEPLIVE:
#else
			buf[len] = '\0';
			printf("Received: %s",buf);
			if(strcmp((char *)buf,"Hello, keepalive!\n")==0)
#endif
				scmd2ppcmdlist(KEEPALIVE_FROM_SERVER, ppcmdata);
#ifndef DEBUG_XXX
				break;
			case M_SERVER_SEND_CONFIG:
				break;
			case M_SERVER_SEND_POLICY:
				break;
			case M_SERVER_SEND_SOFT_V:
				break;
			case M_SERVER_SEND_W_DEV_INFO:
				break;
			case M_SERVER_SEND_BLOCK_CMD:
				break;
			case M_SERVER_SEND_DEBLOCK_CMD:
				break;
			case M_SERVER_GET_WLIST:
				scmd2ppcmdlist(GET_APLIST, ppcmdata);
				break;
			case M_SERVER_GET_STATLIST:
				scmd2ppcmdlist(GET_STALIST, ppcmdata);
				break;
			case M_SERVER_GET_BLKLIST:
				break;
			case M_SERVER_GET_EVENT_LOG:
				break;
			case M_SERVER_GET_NORMAL_LOG:
				break;
			default :
				return -1;
		}
		}while(len > 0);
#endif
	}else if(len == 0){
		sleep(1);
	}else{
		sleep(1);
	}

	return 0;
}

struct reg_info {
	char name[DEFAULT_BUF_LEN];
	char mac[DEFAULT_BUF_LEN];
	char version[DEFAULT_BUF_LEN];
};

//register func
int fcmd_register(__u8 * buf)
{
	struct cmd_req_head * head = (struct cmd_req_head * )buf;
	struct reg_info * data = (struct reg_info *) &buf[sizeof(struct cmd_req_head)];
	
	get_ap_name(data->name, "test");
	get_local_mac(data->mac, IF_NAME);
	get_ap_version(data->version, "R0.1");

	head->pro_version = PROTOCOL_VERSION;
	head->data_len = sizeof(struct cmd_req_head) + sizeof(struct reg_info);
	head->id = W_DEV_REGISTER;
	head->seq_num = 0;

	return head->data_len;
}

int fcmd_keepalive(__u8 * buf)
{
	struct cmd_req_head * head = (struct cmd_req_head * )buf;
	
	head->pro_version = PROTOCOL_VERSION;
	head->data_len = sizeof(struct cmd_req_head);
	head->id = W_DEV_KEEPLIVE;
	head->seq_num = 0;

	return head->data_len;
}

int fcmd_getwlist(__u8 * buf, char * type)
{
	struct cmd_resp_head * head = (struct cmd_resp_head * )buf;
	ListBuf * treebuf = (ListBuf *)&head->success_flag;
	w_node_list **wlisthead, ** wlisttail;

	if(strcmp(type,"aplist")==0){
		wlisthead = &beacon_list_p;
		wlisttail = &beacon_list_tail;
		head->id = M_SERVER_GET_WLIST;
	}else{
		wlisthead = &sta_list_p;
		wlisttail = &sta_list_tail;
		head->id = M_SERVER_GET_STATLIST;
	}

	check_wlist(wlisthead, wlisttail, treebuf);
	head->pro_version = PROTOCOL_VERSION;
	head->data_len = sizeof(struct cmd_resp_head) + treebuf->len;
	head->seq_num = 0;
	head->success_flag = 0;

	return head->data_len;
}

int send_cmd(int fd, ppdata * datap)
{
	__u8 buf[512];
	int len =0;

	if(fd <=0) return -1;

	switch(datap->cmd_name){
		case REGISTER_REQ:
#ifndef DEBUG_XXX
			len = fcmd_register(buf);
#else
			strcpy(buf, "AP2AC,register_test!\n");
			len = 21;
#endif
			break;
		case KEEPALIVE_TO_SERVER:
#ifndef DEBUG_XXX
			len = fcmd_keepalive(buf);
#else
			//memcpy( buf,"\x02\x01\x00\x00\x00\x00",6);
			strcpy(buf, "AP2AC,keepalive_test!\n");
			len = 22;
#endif
			break;
		case DEFAULT_CONFIG:
			return -1;
		case BLOCKING_CMD:
			return -1;
		case UNBLOCKING_CMD:
			return -1;
		case GET_APLIST:
			len = fcmd_getwlist(sendbuf, "aplist");
			return send(fd, sendbuf, len, 0);
		case GET_STALIST:
			len = fcmd_getwlist(sendbuf, "stalist");
			return send(fd, sendbuf, len, 0);
		case GET_BLOCKLIST:
			return -1;
		default :
			return -1;
	}

	return send(fd, buf, len, 0);
}

//sequence_type func

void * ap2ac_task(void *p)
{
	for(;;){
		if(socketfd > 0){
			recv_cmd(socketfd);
		}else{
			sleep(5);
		}
	}

	exit(-1);
}

int init_ppcmd(char *ip, int port)
{
	pthread_t ap2acid_task;
	
	if(1 || ppclient_enable<2)
		return 0;

	sendbuf = malloc(sizeof(ListBuf) + 12);
	if(!sendbuf) 
		return 0;

	create_connect(ip, port);

	//creat recv pthread
	pthread_create(&ap2acid_task, NULL, ap2ac_task, NULL);

	return 1;
}

void main_ppcmd(ppdata * data_p)
{
	pptask * node = NULL;
	if(data_p == NULL) return;
	if(ppclient_enable<2) goto main_ppcmd_out;

	switch(data_p->cmd_name){
		case REGISTER_REQ:
			if((node = find_node_ppcmd(data_p, &list_head )) == NULL)
				goto main_ppcmd_out;
			if(node->data){
				register_check * p_from_tasklist = (register_check *)node->data;
				if( p_from_tasklist->register_state == UNREGIST){
					if(send_cmd(socketfd, data_p) > 0){//register ok
						p_from_tasklist->alive_freshtime = fresh_time;
						p_from_tasklist->register_state = REGISTED;
					}else{
						p_from_tasklist->alive_freshtime = 0;
						p_from_tasklist->register_state = UNREGIST;
					}
				}
			}else{
				register_check * p_tmp = NULL;
				p_tmp = malloc_register_checkdata();
				if(p_tmp == NULL){
					printf("main_ppcmd: malloc for new register_check node err!\n");
					//sleep(1);
					scmd2ppcmdlist(REGISTER_REQ, NULL);
					goto main_ppcmd_out;
				}
				node->data = (void *)p_tmp;
				if(send_cmd(socketfd, data_p) > 0){//register ok
					p_tmp->alive_freshtime = fresh_time;
					p_tmp->register_state = REGISTED;
				}else{
					p_tmp->alive_freshtime = 0;
					p_tmp->register_state = UNREGIST;
				}
			}
			break;
			
		case REGISTER_RESP://register resp
			if((node = find_node_ppcmd(data_p, &list_head )) == NULL)
				goto main_ppcmd_out;
			if(data_p->data){// && node->data){
				//register_check * p_from_tasklist = (register_check *)node->data;
				register_check * p_from_server  = (register_check *)data_p->data;
				if( p_from_server->register_ok == 1){//register false
					//sleep(1);
					scmd2ppcmdlist(REGISTER_REQ, NULL);
				}
			}
			break;

		case KEEPALIVE_TO_SERVER:
			if((node = find_node_ppcmd(data_p, &list_head )) == NULL)
				goto main_ppcmd_out;
			if( node->data){
				register_check * p_from_tasklist = (register_check *)node->data;
				if( p_from_tasklist->register_state == REGISTED){
					send_cmd(socketfd, data_p);
				}
			}
			break;

		case KEEPALIVE_FROM_SERVER:
			if((node = find_node_ppcmd(data_p, &list_head )) == NULL)
				goto main_ppcmd_out;
			if( node->data){
				register_check * p_from_tasklist = (register_check *)node->data;
				if( p_from_tasklist->register_state == REGISTED){
					p_from_tasklist->alive_freshtime = fresh_time;
				}
			}
			break;

		case KEEPALIVE_CHECK:
			if((node = find_node_ppcmd(data_p, &list_head )) == NULL)
				goto main_ppcmd_out;
			if( node->data){
				register_check * p_from_tasklist = (register_check *)node->data;
				if( p_from_tasklist->register_state == UNREGIST ){//for register
					scmd2ppcmdlist(REGISTER_REQ, NULL);
				}else if(fresh_time > (10 + p_from_tasklist->alive_freshtime)){//
					close(socketfd);
					socketfd =-1;
					create_connect(AC_ip, AC_port);
					scmd2ppcmdlist(REGISTER_REQ, NULL);
				}
			}
			break;
			
		case DEFAULT_CONFIG:
			break;
		case BLOCKING_CMD:
			break;
		case UNBLOCKING_CMD:
			break;
		case GET_APLIST:
			send_cmd(socketfd, data_p);
			break;
		case GET_STALIST:
			send_cmd(socketfd, data_p);
			break;
		case GET_BLOCKLIST:
			send_cmd(socketfd, data_p);
			break;
		default :
			break;
	}
main_ppcmd_out:
	wipsd_free(data_p->data);
	wipsd_free(data_p);
}
#endif
