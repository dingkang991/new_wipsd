#ifndef __WIPSD_PUB_H__
#define __WIPSD_PUB_H__

#define WIPSD_MAX_2G_FREQ	  2484 
#define WIPSD_MAX_5G_FREQ	  5825 

typedef struct channelieee_map_t{
	int channel;
	int ieee;
}channelieee_map_t;

int channelieee_convert(int flag, int freq_band, int param);


#endif

