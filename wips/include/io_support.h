#ifndef _IO_SUPPORT_H
#define _IO_SUPPORT_H
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include "zerror.h"
#include "common.h"

#define B_FALSE 0
#define B_TRUE 1


typedef int bool_t;

typedef u_int32_t in_addr_t;
typedef u_int16_t in_port_t;



int fd_set_nonblocking(int fd);
int fd_set_blocking(int fd);
bool_t fd_is_nonblocking(int fd);
int fd_set_close_on_exec(int fd);
int sock_set_reuseaddr(int sfd);
ssize_t sock_get_rcvbuf(int sfd);
int sock_set_rcvbuf(int sfd, size_t size);
ssize_t sock_get_sndbuf(int sfd);
int sock_set_sndbuf(int sfd, size_t size);
int sock_bind_device(int sfd, const char *ifname);
int in_sock_set_hdrincl(int sfd);
int in_sock_bind(int sfd, in_addr_t ip, in_port_t port);
int in_sock_join_group(int sfd, in_addr_t mcip, int ifindex);
int in_sock_leave_group(int sfd, in_addr_t mcip, int ifindex);
int ll_sock_bind(int sfd, int ifindex, unsigned short protocol);

static inline bool_t ignore_intr_errno(int ierrno)
{
	switch (ierrno) {
    		case EINTR:
			return B_TRUE;
		default:
			return B_FALSE;
	}
	/*NOTREACHED*/
}

static inline bool_t ignore_nonblock_errno(int ierrno)
{
	switch (ierrno) {
		//case EINPROGRESS:
#if (defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN)
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			return B_TRUE;
		default:
			return B_FALSE;
	}
	/*NOTREACHED*/
}

static inline ssize_t Recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t n;
	
RESTART:
	n = recv(fd, buf, len, flags);
	if (n < 0 && ignore_intr_errno(errno))
		goto RESTART;
	
	return n;
}

static inline ssize_t Send(int fd, const void *buf, size_t len, int flags)
{
	ssize_t n;
	
RESTART:
	n = send(fd, buf, len, flags);
	if (n < 0 && ignore_intr_errno(errno))
		goto RESTART;
	
	return n;
}

static inline ssize_t Sendmsg(int fd, const struct msghdr *message, int flags)
{
	ssize_t n;
	
RESTART:
	n = sendmsg(fd, message, flags);
	if (n < 0 && ignore_intr_errno(errno))
		goto RESTART;
	
	return n;
}

#endif /*_IO_SUPPORT_H*/


