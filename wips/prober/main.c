#include <stdio.h>  
#include <stdlib.h>  
  
#include <string.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include "uloop.h"
#include "usock.h"

void main(void)
{
	int fd;
	static int i;
	static count=0 ;
   struct sockaddr_in address;//处理网络通信的地址  
  
    bzero(&address,sizeof(address));  
    address.sin_family=AF_INET;  
    address.sin_addr.s_addr=inet_addr("127.0.0.1");//这里不一样  
    address.sin_port=htons(13524);  
  
	static struct uloop_fd client;
	fd = usock(USOCK_UDP | USOCK_IPV4ONLY | USOCK_NUMERIC, NULL, "13525");
	do{
	int i=0;
	char buf[128];
	snprintf(buf,128,"((%d))",count++);
	i = sendto(fd,buf,128,0,(struct sockaddr*)&address,sizeof(address));
	printf("seng msg :%d\n",i);	
//	sleep (5);
	}while(1);
return;
}

