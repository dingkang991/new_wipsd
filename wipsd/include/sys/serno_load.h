#ifndef __SERNO_LOAD_H__
#define __SERNO_LOAD_H__

#define SERNO_LEN 32
struct __serno_info{
	char serno[SERNO_LEN];
};

struct __serno_info serno_info;
extern struct __serno_info serno_info;
#endif
