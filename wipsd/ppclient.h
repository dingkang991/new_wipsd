//probe_point_client: ppclient.c's header file
#ifndef _H_PPCLIENT
#define _H_PPCLIENT

//#include "wipsd.h"

//data
typedef struct pptask
{
	struct pptask * last;
	struct pptask * next;
	void * data;
	long sequence;
	int refresh_time;
	int retries;
	int cmd_id;
	int cmd_name;
}pptask;

typedef struct ppdata
{
	void * data;
	int cmd_id;
	int cmd_name;
	int sequence_type;
}ppdata;

#define REGISTED 1
#define UNREGIST 0
typedef struct register_check
{
	int register_state;
	int alive_freshtime;
	int register_ok;
}register_check;

//ppcmd CMD
enum {
	REGISTER_REQ = 0,/*AP2AC_REGISTER*/
	REGISTER_RESP,

	KEEPALIVE_TO_SERVER, 
	KEEPALIVE_FROM_SERVER,
	KEEPALIVE_CHECK,

	DEFAULT_CONFIG,
	BLOCKING_CMD,
	UNBLOCKING_CMD,
	GET_APLIST,
	GET_STALIST,
	GET_BLOCKLIST
};

//func
//初始化函数
int init_ppcmd(char *ip, int port);

//ppcmd主函数
void main_ppcmd(ppdata * data_p);

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

//#define DEBUG_XXX 1

extern int scmd2ppcmdlist(int cmd, ppdata * datap);
#endif

