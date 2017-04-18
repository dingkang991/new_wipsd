#ifndef __common_h__
#define __common_h__

#include  <endian.h>

#ifndef __packed
#define __packed    __attribute__((__packed__))
#endif

#ifndef __force
#define __force __attribute__((__force__))
#endif

#define _BYTE_ORDER  _BIG_ENDIAN

#define SSID_BUFSIZE	63
#define SSID_BUFSIZE_D	(SSID_BUFSIZE+1)
#define ETH_ALEN 6

typedef unsigned char           u8,_u8,__u8;
typedef unsigned short          u16,_u16,__u16;
typedef unsigned int            u32,_u32,__u32;
typedef char 					s8;


#define get_unaligned(ptr)	\
({	\
struct __attribute__((packed)) {	\
typeof(*(ptr)) __v;	\
} *__p = (void *) (ptr);	\
__p->__v;	\
})


#endif
