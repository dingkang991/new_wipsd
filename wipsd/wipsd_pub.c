#include "wipsd_pub.h"

//flag: 0 for channel to ieee; !0 for ieee to channel.
int channelieee_convert(int flag, int freq_band, int param)
{
	static int split_2g5g = 0;
	int i = 0;

	channelieee_map_t channelieee_map[] =
	{
			//2G
			{1,2412},
			{2,2417},
			{3,2422},
			{4,2427},
			{5,2432},
			{6,2437},
			{7,2442},
			{8,2447},
			{9,2452},
			{10,2457},
			{11,2462},
			{12,2467},
			{13,2472},
			{14,WIPSD_MAX_2G_FREQ},
			//5G
			{184,4920},
			{185,4925},
			{186,4930},
			{187,4935},
			{188,4940},
			{189,4945},
			{192,4960},
			{196,4980},
			{7,5035},
			{8,5040},
			{9,5045},
			{11,5055},
			{12,5060},
			{16,5080},
			{34,5170},
			{36,5180},
			{38,5190},
			{40,5200},
			{42,5210},
			{44,5220},
			{46,5230},
			{48,5240},
			{52,5260},
			{56,5280},
			{60,5300},
			{64,5320},
			{100,5500},
			{104,5520},
			{108,5540},
			{112,5560},
			{116,5580},
			{120,5600},
			{124,5620},
			{128,5640},
			{132,5660},
			{136,5680},
			{140,5700},
			{149,5745},
			{153,5765},
			{157,5785},
			{161,5805},
			{165,WIPSD_MAX_5G_FREQ}
	};
	
	
	if (split_2g5g == 0){
		
		for (i =0; i < sizeof(channelieee_map)/sizeof(channelieee_map_t); i++){
			
			if (channelieee_map[i].ieee == WIPSD_MAX_2G_FREQ){
				split_2g5g = i;
			}
		}
	}
	
	if (flag == 0){
		
		if (freq_band == 2){
			
			for (i = 0; i <= split_2g5g; i ++){

				if (channelieee_map[i].channel == param){
					return channelieee_map[i].ieee;
				}
			}
		}else if (freq_band == 5) {
				
			for (i = split_2g5g + 1; i < sizeof(channelieee_map)/sizeof(channelieee_map_t); i ++){

				if (channelieee_map[i].channel == param){
					return channelieee_map[i].ieee;
				}
			}
		}
	}

	if (flag != 0){
		
		if (param > WIPSD_MAX_2G_FREQ){
			
			for (i = split_2g5g + 1; i < sizeof(channelieee_map)/sizeof(channelieee_map_t); i ++){

				if (channelieee_map[i].ieee == param){
					return channelieee_map[i].channel;
				}
			}
		}else{
		
			for (i = 0; i <= split_2g5g; i ++){

				if (channelieee_map[i].channel == param){
					return channelieee_map[i].channel;
				}
			}
		}
	}

	return -1;
}

