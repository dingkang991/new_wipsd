#ifndef __WIPSD_SAVE_H__
#define __WIPSD_SAVE_H__

#ifdef HAVE_SAVE_THREAD

#define PATH "/tmp/wireless_s"
#define dir_prefix "/usr/hls/log/stats"
#define APP_SAVE_INTVAL 600
#define APP_SAVE_SIZE (6*24*31)	// 保存一个月

//static int start_flag = 0;

struct save_head {
	int index;
	time_t timestamp;
};

struct save_elem_wnode{
	int ap_num;
	int station_num;
	//int reserve;
};
#endif

#endif
