#include <asm/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#define PATH "/tmp/wireless_s"
#define C_PATH "/tmp/"
#include <inttypes.h>
#include "wipsd_wnode.h"

#define gMAX (sizeof(ListBuf))

__u8 atoix(char * str)
{
	if(*str > 47 && *str < 58) return (*str - 48);
	if(*str > 64 && *str < 71) return (*str - 55);
	if(*str > 96 && *str < 103) return (*str - 87);
	printf("\nPlease input mac address like that format 01:23:45:ab:cd:ef .\n\n");
	exit(-1);
}

void str2mac(__u8 * mac, char * str)
{
	mac[0]=atoix(&str[0])*16 + atoix(&str[1]);
	mac[1]=atoix(&str[3])*16 + atoix(&str[4]);
	mac[2]=atoix(&str[6])*16 + atoix(&str[7]);
	mac[3]=atoix(&str[9])*16 + atoix(&str[10]);
	mac[4]=atoix(&str[12])*16 + atoix(&str[13]);
	mac[5]=atoix(&str[15])*16 + atoix(&str[16]);
}

void dump_wnode(struct w_node *node )
{
	printf("===========dump a wnode start==========\n");
	printf("|	alert-----------: 0x%08X%08X%08X%08X%08X\n", 
		node->alert[4], node->alert[3], 
		node->alert[2], node->alert[1], node->alert[0]);
	printf("|	up_time---------: %d\n", (int)node->up_time);
	printf("|	last_time-------: %d\n", (int)node->last_time);
	printf("|	refresh_time----: %d\n", (int)node->refresh_time);
	printf("|	beacon_c--------: %d\n", node->beacon_c);
	printf("|	timestamp-------: 0x%"PRIX64"\n", node->timestamp);
//	printf("|	ssidn_type------: %s\n", node->ssidn_type ? "sta":"ap");
	printf("|	capability_info-: %d\n", node->capability_info);
	printf("|	channel---------: %d\n", node->channel);
	printf("|	freq_band ------: %d\n", node->freq_band);
	printf("|	interval--------: %d\n", node->interval);
	printf("|	reason_code-----: %d\n", node->reason_code);
	printf("|	id--------------: %d\n", node->id);
	printf("|	block-----------: %d\n", node->block);
	printf("|	rates-----------: %d\n", node->rates);
	printf("|	duration--------: %d\n", node->duration);
	printf("|	sequence_num----: %d\n", node->sequence_num);
	printf("|	vendor----------: %s\n", node->vendor);
	printf("|	sec_type--------: %s\n", node->sec_type);
	printf("|	ipv4------------: %s\n", node->ipv4);
	printf("|	ssid------------: %s\n", node->ssid);
	printf("|	name------------: %s\n", node->name);
	printf("|	bssid-----------: "MACSTR"\n", MAC2STR(node->bssid));
	printf("|	mac-------------: "MACSTR"\n", MAC2STR(node->mac));
	printf("|	lan_mac---------: "MACSTR"\n", MAC2STR(node->lan_mac));
	printf("|	essid_id--------: "MACSTR"\n", MAC2STR(node->essid_id));
	printf("|	child_num-------: %d\n", node->child_num);
	printf("|	sta_num---------: %d\n", node->sta_num);
	printf("|	g_rates---------: %s\n", node->g_rates ? "supportG":"UNsupportG");
	printf("|	n_rates---------: %s\n", node->n_rates ? "supportN":"UNsupportN");
	printf("|	signal----------: %d\n", node->signal);
	printf("|	noise-----------: %d\n", node->noise);
//	printf("|	node_type-------: 0x%02X	[ bit7: bit6: bit5:wps bit4:INaplist(0)_INstalist(1) | bit3:wds bit2:ad-hoc bit1:sta bit0:ap ]\n", node->node_type);
	printf("|	node_type-------: %s%s%s%s%s%s\n",
								(node->node_type & 1<<0 ) ? "ap + ":"",
								(node->node_type & 1<<1 ) ? "sta + ":"",
								(node->node_type & 1<<2 ) ? "ad-hoc + ":"",
								(node->node_type & 1<<3 ) ? "wds + ":"",
								(node->node_type & 1<<5 ) ? "wps + ":"",
								(node->node_type & 1<<4 ) ? "INstalist":"INaplist"
								);
	printf("|	sta_num---------: %d\n", node->sta_num);
	printf("|	authed----------: %s\n", node->authed ? "yes":"no");
	printf("|	hide_ssid-------: %s\n", node->hide_ssid ? "yes":"no");
	printf("|	block_method----: %d\n", node->block_method);
	printf("+--------------------------------------\n");
}

void chech_treebuf_getwlist(ListBuf *treebuf,char * nodeMac, char print_type)
{
	struct w_node *node;
	int node_num	= 0;
	int i;
	__u8 mac[6];

	if(print_type){
		if(!treebuf )return;
	}else{
		if(!treebuf || !nodeMac)return;
		str2mac(mac,nodeMac);
	}
	node_num = treebuf->len / sizeof(struct w_node) ;
	printf("chech_treebuf_g node_num[%d]\n",node_num); 

	for(i=0; i<node_num; i++) {
		node = (struct w_node *)(treebuf->buf+ i*sizeof(struct w_node));
		if(print_type){
			dump_wnode(node);
		}else{
			if(memcmp( node->mac,mac,6) == 0){
				printf("Find the node in chech_treebuf_g[%02x:%02x:%02x:%02x:%02x:%02x] GGG\n", 
					node->mac[0], node->mac[1], node->mac[2], 
					node->mac[3], node->mac[4], node->mac[5]);//
				dump_wnode(node);
			}
		}
	}
}

int main(int argc,char *argv[])
{
	int cfd,len;
	struct sockaddr_un un;
	char buf[gMAX],*str="Nothing";
	int recv_again_num=0;
	if(argc>1)
		str=argv[1];
	if((strcmp(str,"aplist")!=0) 
		&& (strcmp(str,"stalist")!=0) 
		&& (strcmp(str,"cara")!=0) 
		&& (strcmp(str,"clean_cara")!=0) 
		&& (strcmp(str,"check_list")!=0)
		&& (strcmp(str,"update_wconfig")!=0)
		&& (strcmp(str,"refd")!=0) 
		&& (strcmp(str,"cc=3")!=0) 
		&& (strcmp(str,"cc=2")!=0) 
		&& (strcmp(str,"cc=1")!=0)
		&& (strcmp(str,"bd=2")!=0)
		&& (strcmp(str,"bd=5")!=0)
		&& (strcmp(str,"bd=25")!=0)
		&& (strcmp(str,"print_pac")!=0)
		&& ((strncmp(str, "ssid[", 5)!=0))
		&& ((strncmp(str, "wnode", 5)!=0))
		&& (strcmp(str,"TREE_GET_ESSID_NAME_ID")!=0) 
		&& ((strncmp(str, "TREE_GET_BY_ESSID_ID", 20)!=0))
		&& ((strncmp(str, "TREE_GET_BY_A_ESSID", 19)!=0))
		&& (strcmp(str,"TREE_GET_ALL_ESSID")!=0) 
		&& ((strncmp(str, "TREE_GET_BY_CHANNEL", 19)!=0))
		&& (strcmp(str,"TREE_GET_ALL_CHANNEL")!=0) 
		&& ((strncmp(str, "TREE_GET_ISLANDSTA_BY_CHANNEL", 29)!=0))
		&& (strcmp(str,"TREE_GET_ISLANDSTA_ALL_CHANNEL")!=0) 
		){
		printf("Command err!\n");
		printf("usage: ./getwlist stalist  \n"
			"or     ./getwlist aplist \n"
			"or     ./getwlist cara \n"
			"or     ./getwlist clean_cara \n"
			"or     ./getwlist check_list \n"
			"or     ./getwlist cc=X \n"
			"or     ./getwlist bd=X \n"
			"or     ./getwlist print_pac \n"
			"or     ./getwlist ssid[your ssid]iface[athX]ch[channel]type[non/wep/wpa]\n"
			"or     ./getwlist wnode \n"
			"or     ./getwlist TREE_GET_ESSID_NAME_ID \n"
			"or     ./getwlist TREE_GET_BY_ESSID_ID \n"
			"or     ./getwlist TREE_GET_BY_A_ESSID \n"
			"or     ./getwlist TREE_GET_ALL_ESSID \n"
			"or     ./getwlist TREE_GET_BY_CHANNEL \n"
			"or     ./getwlist TREE_GET_ALL_CHANNEL \n"
			"or     ./getwlist TREE_GET_ISLANDSTA_BY_CHANNEL \n"
			"or     ./getwlist TREE_GET_ISLANDSTA_ALL_CHANNEL \n"
			"\n");
		exit(1);
	}

get_wips_data_again:
	memset(buf, 0 , gMAX);
	if((cfd=socket(AF_UNIX,SOCK_STREAM,0))==-1){
		perror("Fail to socket");
		exit(1);
	}

	memset(&un,0,sizeof(struct sockaddr_un));
	un.sun_family=AF_UNIX;
	sprintf(un.sun_path,"%s%d",C_PATH,getpid());
	len=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	unlink(un.sun_path);

	if(bind(cfd,(struct sockaddr *)&un,len)==-1){
		perror("Fail to bind");
		exit(1);
	}

	if(chmod(un.sun_path,S_IRWXU)<0){
		perror("Fail to chmod");
		exit(1);
	}

	memset(&un,0,sizeof(struct sockaddr_un));
	un.sun_family=AF_UNIX;
	strcpy(un.sun_path,PATH);

	len=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	if(connect(cfd,(struct sockaddr *)&un,len)<0){
		perror("getwlist Fail to connect");
		exit(1);
	}

	if(write(cfd,str,strlen(str))==-1){
		perror("Fail to write");
		exit(1);
	}
	
	if(strcmp(str,"cara")==0){
		sleep(5);
		goto exit_here;
	}
	if(strcmp(str,"clean_cara")==0)goto exit_here;
	if(strcmp(str,"check_list")==0)goto exit_here;
	if(strcmp(str,"print_pac")==0)goto exit_here;
	if(strcmp(str,"update_wconfig")==0)goto exit_here;
	if(strcmp(str,"refd")==0)goto exit_here;
	if(strcmp(str,"cc=3")==0)goto exit_here;
	if(strcmp(str,"cc=2")==0)goto exit_here;
	if(strcmp(str,"cc=1")==0)goto exit_here;
	if(strcmp(str,"bd=2")==0)goto exit_here;
	if(strcmp(str,"bd=5")==0)goto exit_here;
	if(strcmp(str,"bd=25")==0)goto exit_here;
	if(strncmp(str, "ssid[", 5)==0)goto exit_here;

{
	char recvnum=0, *recv_bufname, i, recv_head[20];
	int ret;
	if((ret = read( cfd, recv_head, 20))==-1){
		perror("<!-- Fail to read 001 -->\n");
		//printf("<!-- get data from wips timeout -->\n");
		return 0;
	}else if(memcmp( recv_head,"send_start",10) == 0){
		if(recv_head[10] > 0 ) recvnum = recv_head[10];
	}else if(recv_again_num < 3){
		close(cfd);
		recv_again_num++;
		goto get_wips_data_again;
	}else{
		close(cfd);
		return 0;
	}
	if(write(cfd,"ACK",3)==-1){
		perror("<!-- Fail to write ACK -->\n");
		if(recv_again_num < 3){
			close(cfd);
			recv_again_num++;
			goto get_wips_data_again;
		}else{
			close(cfd);
			return 0;
		}
	}
	
	len = 0;
	for(i=0; i < recvnum; i++){
		recv_bufname = buf + len;
		if((ret = read(cfd,recv_bufname,(gMAX - len)))==-1){
			perror("<!-- Fail to read 002 -->\n");
			ret = write(cfd, "recv_err", 9);
			if(recv_again_num < 3){
				close(cfd);
				recv_again_num++;
				goto get_wips_data_again;
			}else{
				close(cfd);
				return 0;
			}
		}else if(memcmp( recv_bufname,"send_err",8) == 0){
			if(recv_again_num < 3){
				close(cfd);
				recv_again_num++;
				goto get_wips_data_again;
			}else{
				close(cfd);
				return 0;
			}
		}else if(write(cfd,"ACK",3)==-1){
			if(recv_again_num < 3){
				close(cfd);
				recv_again_num++;
				goto get_wips_data_again;
			}else{
				close(cfd);
				return 0;
			}
		}
		len += ret;
	}

	//printf("w_node_len[%d]\n",sizeof(struct w_node));
	if(len < (*((int *)buf) + 4)) {
		if(recv_again_num < 3){
			close(cfd);
			recv_again_num++;
			goto get_wips_data_again;
		}else{
			close(cfd);
			return 0;
		}
	}
}

	//your code
	ListBuf *treebuf =(ListBuf *)buf;
	if(argc==3){
		str=argv[2];
		chech_treebuf_getwlist(treebuf, argv[2], 0);
	}else{
		printf("socket_recv: %d\n",len);
		chech_treebuf_getwlist(treebuf, NULL, 1);
	}
exit_here:
	close(cfd);
	return 0;
}
