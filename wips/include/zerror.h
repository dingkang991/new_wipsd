#ifndef _ZERROR_H
#define _ZERROR_H

#define E_ZBASE 10

#define E_SYSC_OPEN -(E_ZBASE + 1)
#define E_SYSC_READ -(E_ZBASE + 2)
#define E_SYSC_WRITE -(E_ZBASE + 3)
#define E_SYSC_FCNTL -(E_ZBASE + 4)
#define E_SYSC_STAT -(E_ZBASE + 5)
#define E_SYSC_STATFS -(E_ZBASE + 6)
#define E_SYSC_MKDIR -(E_ZBASE + 7)
#define E_SYSC_FTRUNCATE -(E_ZBASE + 8)
#define E_SYSC_UNLINK -(E_ZBASE + 9)
#define E_SYSC_RENAME -(E_ZBASE + 10)
#define E_SYSC_SELECT -(E_ZBASE + 11)
#define E_SYSC_SOCKET -(E_ZBASE + 12)
#define E_SYSC_GETSOCKOPT -(E_ZBASE + 13)
#define E_SYSC_SETSOCKOPT -(E_ZBASE + 14)
#define E_SYSC_BIND -(E_ZBASE + 15)
#define E_SYSC_RECV -(E_ZBASE + 16)
#define E_SYSC_SEND -(E_ZBASE + 17)
#define E_SYSC_SEND_NETDOWN -(E_ZBASE + 18)
#define E_SYSC_SENDMSG -(E_ZBASE + 19)
#define E_SYSC_RECVMSG -(E_ZBASE + 20)
#define E_SYSC_SYSTEM -(E_ZBASE + 21)

#define E_ZEBRA_XMALLOC -(E_ZBASE + 22)
#define E_ZEBRA_SIGNAL_SET -(E_ZBASE + 23)
#define E_ZEBRA_THREAD_ADD_READ -(E_ZBASE + 24)
#define E_ZEBRA_THREAD_ADD_WRITE -(E_ZBASE + 25)
#define E_ZEBRA_THREAD_ADD_TIMER -(E_ZBASE + 26)
#define E_ZEBRA_THREAD_ADD_USTIMER -(E_ZBASE + 27)

#define E_EXEC_ERROR -(E_ZBASE + 28)
#define E_WSIGNALED -(E_ZBASE + 29)
#define E_FLOCK_FAIL -(E_ZBASE + 30)
#define E_NOT_DIR -(E_ZBASE + 31)
#define E_NOT_REGFILE -(E_ZBASE + 32)
#define E_MOUNTPOINT -(E_ZBASE + 33)
#define E_TRUNC_PATH -(E_ZBASE + 34)
#define E_TRUNC_IFNAME -(E_ZBASE + 35)
#define E_FDU_NOOPEN -(E_ZBASE + 36)
#define E_PARSE_OAMH -(E_ZBASE + 37)
#define E_PARSE_OAMDATA -(E_ZBASE + 38)
#define E_TRUNC_OAMDATA -(E_ZBASE + 39)
#define E_OIPC_RPC -(E_ZBASE + 40)
#define SYSCE_MSG 
#define FAIL_MSG
#endif /*_ZERROR_H*/


