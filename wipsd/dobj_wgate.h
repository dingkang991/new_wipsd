#ifndef DOBJ_WGATE_H
#define DOBJ_WGATE_H

#include <linux/types.h>

int dobj_wgate_init(void);
int dobj_wgate_destroy(void);

int dobj_wgate_update(__u8* mac, __u8* ip);
int dobj_wgate_query(__u8* mac, __u8* ip);

#endif
