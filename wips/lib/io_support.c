#include <linux/if_packet.h>
#include "io_support.h"

int fd_set_nonblocking(int fd)
{
	int flags;
	
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		SYSCE_MSG("fcntl()\n");
		return E_SYSC_FCNTL;
	}
	
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		SYSCE_MSG("fcntl()\n");
		return E_SYSC_FCNTL;
	}
	
	return 0;
}

int fd_set_blocking(int fd)
{
	int flags;
	
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		SYSCE_MSG("fcntl()\n");
		return E_SYSC_FCNTL;
	}
	
	if (fcntl(fd, F_SETFL, flags & (~O_NONBLOCK)) < 0) {
		SYSCE_MSG("fcntl()\n");
		return E_SYSC_FCNTL;
	}
	
	return 0;
}

bool_t fd_is_nonblocking(int fd)
{
	int flags;
	
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		SYSCE_MSG("fcntl()\n");
		return B_FALSE;
	}
	
	return ((flags & O_NONBLOCK) ? B_TRUE : B_FALSE);
}

int fd_set_close_on_exec(int fd)
{
	int flags;
	
	if ((flags = fcntl(fd, F_GETFD)) < 0) {
		SYSCE_MSG("fcntl()\n");
		return E_SYSC_FCNTL;
	}
	
	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
		SYSCE_MSG("fcntl()\n");
		return E_SYSC_FCNTL;
	}
	
	return 0;
}

int sock_set_reuseaddr(int sfd)
{
	int ret;
	int on = 1;
	
	ret = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, 
	                 (char *)&on, sizeof(int));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

ssize_t sock_get_rcvbuf(int sfd)
{
	int ret;
	int val = 0;
	int len = sizeof(int);
	
	ret = getsockopt(sfd, SOL_SOCKET, SO_RCVBUF, 
	                 (char *)&val, &len);
	if (ret < 0) {
		SYSCE_MSG("getsockopt()\n");
		return E_SYSC_GETSOCKOPT;
	}
	
	return val;
}

int sock_set_rcvbuf(int sfd, size_t size)
{
	int ret;
	int val = (int)size;
	
	ret = setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, 
	                 (char *)&val, sizeof(int));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

ssize_t sock_get_sndbuf(int sfd)
{
	int ret;
	int val = 0;
	int len = sizeof(int);
	
	ret = getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, 
	                 (char *)&val, &len);
	if (ret < 0) {
		SYSCE_MSG("getsockopt()\n");
		return E_SYSC_GETSOCKOPT;
	}
	
	return val;
}

int sock_set_sndbuf(int sfd, size_t size)
{
	int ret;
	int val = (int)size;
	
	ret = setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, 
	                 (char *)&val, sizeof(int));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

int sock_bind_device(int sfd, const char *ifname)
{
	int ret;
	struct ifreq ifreq;
	
	if (strlen(ifname) > IFNAMSIZ - 1) {
		FAIL_MSG("the length of interface name is too long\n");
		return E_TRUNC_IFNAME;
	}
	
	bzero(&ifreq, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ - 1);
	
	ret = setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, 
	                 (char *)&ifreq, sizeof(struct ifreq));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

static void sockaddr_in_fill(struct sockaddr_in *saddr_in, in_addr_t ip, in_port_t port)
{
	if (!ip)
		ip = INADDR_ANY;
	
	bzero(saddr_in, sizeof(struct sockaddr_in));
	saddr_in->sin_family = AF_INET;
	saddr_in->sin_addr.s_addr = htonl(ip);
	saddr_in->sin_port = htons(port);
}

int in_sock_set_hdrincl(int sfd)
{
	int ret;
	int on = 1;
	
	ret = setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, 
	                 (char *)&on, sizeof(int));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

int in_sock_bind(int sfd, in_addr_t ip, in_port_t port)
{
	int ret;
	struct sockaddr_in saddr_in;
	
	sockaddr_in_fill(&saddr_in, ip, port);
	
	ret = bind(sfd, (struct sockaddr *)&saddr_in, sizeof(struct sockaddr_in));
	if (ret < 0) {
		SYSCE_MSG("bind()\n");
		return E_SYSC_BIND;
	}
	
	return 0;
}

int in_sock_join_group(int sfd, in_addr_t mcip, int ifindex)
{
	int ret;
	struct ip_mreqn mreq;
	
	bzero(&mreq, sizeof(struct ip_mreqn));
	mreq.imr_multiaddr.s_addr = htonl(mcip);
	mreq.imr_ifindex = ifindex;
	
	ret = setsockopt(sfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	                 (char *)&mreq, sizeof(struct ip_mreqn));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

int in_sock_leave_group(int sfd, in_addr_t mcip, int ifindex)
{
	int ret;
	struct ip_mreqn mreq;
	
	bzero(&mreq, sizeof(struct ip_mreqn));
	mreq.imr_multiaddr.s_addr = htonl(mcip);
	mreq.imr_ifindex = ifindex;
	
	ret = setsockopt(sfd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
	                 (char *)&mreq, sizeof(struct ip_mreqn));
	if (ret < 0) {
		SYSCE_MSG("setsockopt()\n");
		return E_SYSC_SETSOCKOPT;
	}
	
	return 0;
}

static void sockaddr_ll_fill(struct sockaddr_ll *saddr_ll, int ifindex, unsigned short protocol)
{
	bzero(saddr_ll, sizeof(struct sockaddr_ll));
	saddr_ll->sll_family = AF_PACKET;
	saddr_ll->sll_protocol = htons(protocol);
	saddr_ll->sll_ifindex = ifindex;
}

int ll_sock_bind(int sfd, int ifindex, unsigned short protocol)
{
	int ret;
	struct sockaddr_ll saddr_ll;
	
	sockaddr_ll_fill(&saddr_ll, ifindex, protocol);
	
	ret = bind(sfd, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
	if (ret < 0) {
		SYSCE_MSG("bind()\n");
		return E_SYSC_BIND;
	}
	
	return 0;
}

