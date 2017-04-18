#ifndef _H_FAKEAP
#define _H_FAKEAP

#include "wipsd_wnode.h"

enum {
	FAKE_WPA,
	FAKE_WEP,
	FAKE_OPEN,

	ADD_AP,
	DEL_AP
};

typedef struct created_ap
{
	int sec_type;
	char ssid[SSID_BUFSIZE_D];//ssid
}created_ap;

void create_fakeap(char * iface, char * ssid, int ch, char type);
void auto_operating_fakeap(struct w_node * node, int init_mem);

#endif

