

/*includes ofter used*/
#ifndef		__unp_h
#define		__unp_h

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<time.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<netdb.h>
#include	<signal.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/stat.h>
#include	<sys/uio.h>
#include	<unistd.h>
#include	<sys/wait.h>
#include	<sys/un.h>
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<linux/types.h>
#include	<linux/unistd.h>
#include	<ctype.h>
#include <assert.h>

#ifdef		HAVE_SYS_SELECT_H
#include	<sys/select.h>
#endif

#ifdef		HAVE_POLL_H
#include	<poll.h>
#endif

#ifdef		HAVE_STRINGS_H
#include	<strings.h>
#endif

#ifdef		HAVE_SYS_IOCTL_H
#include	<sys/ioctl.h>
#endif

#ifdef		HAVE_SYS_SOCKIO_H
#include	<sys/sockio.h>
#endif

#include	<pthread.h>

#define		SA		struct sockaddr
#define		FILE_MODE	(S_IRUSR | S_IWUSR | S_IRGRP |S_IROTH)
#define		LISTENQ		1024

#define		min(a,b)	(((a)<(b))? (a):(b))
#define		max(a,b)	(((a)>(b))? (a):(b))

#define		swap(s,a,b)	{	\
		s	__t;		\
		__t=*(a);               \
		*(a)=*(b);              \
		*(b)=__t;               \
}


#endif



