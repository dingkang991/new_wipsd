#ifndef __PUB_H__
#define __PUB_H__

#ifdef __KERNEL__
#include <linux/ctype.h>
#else
#include <ctype.h>
#endif

#define LENGTH_OF_LINE    100

/*
*convert ascii string to ethernet mac address,
*mac address format AA:BB:CC:DD:EE:FF,
*colon is not needed,
*later add support for cisco style AAAA.BBBB.CCCC
*/
#define ETH_ALEN 6

static inline int inet_atoe(char *bufp, char addr[6])
{
	int i, j;
	unsigned char val;
	unsigned char c;
		
	for (i = 0 ; i < ETH_ALEN ; i++) {
		val = 0;

		/* We might get a semicolon here - not required. */
		if (i && (*bufp == ':')) {
			bufp++;
		}

		for (j=0 ; j<2 ; j++) {
			c = *bufp;
			
			if (c==0 && j && i==5)
				break;
			else if (c >= '0' && c <= '9') {
				c -= '0';
			} else if (c >= 'a' && c <= 'f') {
				c -= ('a' - 10);
			} else if (c >= 'A' && c <= 'F') {
				c -= ('A' - 10);
			} else if (j && c == ':') {
				break;
			} else {
				return -1;
			}
			++bufp;
			val <<= 4;
			val += c;
		}
		*addr++ = val;
	}

	while (isspace(*bufp))
		bufp++;
	if (*bufp==0)
		return 0;		/* Error if we don't end at end of string. */
	else return -1;
}

#include <asm/types.h>

#ifdef __KERNEL__
#include <asm/byteorder.h>

static inline __u64 ntoh64(__u64 x)
{
#ifdef __BIG_ENDIAN
	return x;
#else
#ifndef __LITTLE_ENDIAN
#error "ENDIAN not defined\n"
#endif
	return	((x & (__u64)0x00000000000000ffULL) << 56) | 
		((x & (__u64)0x000000000000ff00ULL) << 40) |
		((x & (__u64)0x0000000000ff0000ULL) << 24) |
		((x & (__u64)0x00000000ff000000ULL) <<  8) |
		((x & (__u64)0x000000ff00000000ULL) >>  8) |
		((x & (__u64)0x0000ff0000000000ULL) >> 24) |
		((x & (__u64)0x00ff000000000000ULL) >> 40) | 
		((x & (__u64)0xff00000000000000ULL) >> 56); 
#endif
}

static inline __u64 hton64(__u64 x)
{
#ifdef __BIG_ENDIAN
	return x;
#else
#ifndef __LITTLE_ENDIAN
#error "ENDIAN not defined\n"
#endif
	return	((x & (__u64)0x00000000000000ffULL) << 56) | 
		((x & (__u64)0x000000000000ff00ULL) << 40) |
		((x & (__u64)0x0000000000ff0000ULL) << 24) |
		((x & (__u64)0x00000000ff000000ULL) <<  8) |
		((x & (__u64)0x000000ff00000000ULL) >>  8) |
		((x & (__u64)0x0000ff0000000000ULL) >> 24) |
		((x & (__u64)0x00ff000000000000ULL) >> 40) | 
		((x & (__u64)0xff00000000000000ULL) >> 56); 
#endif
}
#else	/*__KERNEL__*/
#include <endian.h>

static inline __u64 ntoh64(__u64 x)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	return x;
#else
#if  __BYTE_ORDER != __LITTLE_ENDIAN
#error "ENDIAN not defined\n"
#endif
	return	((x & (__u64)0x00000000000000ffULL) << 56) | 
		((x & (__u64)0x000000000000ff00ULL) << 40) |
		((x & (__u64)0x0000000000ff0000ULL) << 24) |
		((x & (__u64)0x00000000ff000000ULL) <<  8) |
		((x & (__u64)0x000000ff00000000ULL) >>  8) |
		((x & (__u64)0x0000ff0000000000ULL) >> 24) |
		((x & (__u64)0x00ff000000000000ULL) >> 40) | 
		((x & (__u64)0xff00000000000000ULL) >> 56); 
#endif
}

static inline __u64 hton64(__u64 x)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	return x;
#else
#if  __BYTE_ORDER != __LITTLE_ENDIAN
#error "ENDIAN not defined\n"
#endif
	return	((x & (__u64)0x00000000000000ffULL) << 56) | 
		((x & (__u64)0x000000000000ff00ULL) << 40) |
		((x & (__u64)0x0000000000ff0000ULL) << 24) |
		((x & (__u64)0x00000000ff000000ULL) <<  8) |
		((x & (__u64)0x000000ff00000000ULL) >>  8) |
		((x & (__u64)0x0000ff0000000000ULL) >> 24) |
		((x & (__u64)0x00ff000000000000ULL) >> 40) | 
		((x & (__u64)0xff00000000000000ULL) >> 56); 
#endif
}
#endif	/*__KERNEL__*/

#endif

