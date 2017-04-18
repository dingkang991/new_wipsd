

#ifndef _DEV_MASK_H
#define _DEV_MASK_H

/*
*DEV_MASK_SIZE: how many devices can do multicast routing in a given time.
*/
#define DEV_MASK_SIZE		32
/*this priority should be higher than other notifier*/
#define DEV_MASK_PRIORITY	100
typedef __u32			dev_mask_t;


int dev_mask_init(void);
int dev_mask_deinit(void);
int dev_to_mask(struct net_device *dev[DEV_MASK_SIZE], dev_mask_t *mask);
int mask_to_dev(struct net_device *dev[DEV_MASK_SIZE], dev_mask_t mask);


#endif


