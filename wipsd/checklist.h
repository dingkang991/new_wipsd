// checklist.c's header file
#ifndef _H_CHECKLIST
#define _H_CHECKLIST

//data
typedef struct pollfunc
{
    struct pollfunc * next;
    int (*check_func)(struct w_node * wnode);
}pollfunc;

typedef struct fea_ssid
{
    struct fea_ssid * next;
    char* ssid;//[SSID_BUFSIZE_D];
    __u8 type;
}fea_ssid;

#if 0
#define FEATURE_INTERNAL_SSID "WF0001"
#endif

//func
void init_pollnode(void);
int pollingnode(struct w_node * wnode);
int add_internal_ssid(char * ssidname, fea_ssid ** i_ssid);
extern fea_ssid * internal_ssid;

#endif

