#ifndef WGATE_HASH_H
#define WGATE_HASH_H

extern int init_wgate_hash(const char* dbfilename);
extern int update_wgate_hash(void);
extern int is_wgate_hash_null(void);
extern const unsigned char* query_wgate_hash(const unsigned char* mac);
extern unsigned char* query_wgate_hash_with_ip(unsigned char* mac, unsigned char* ip);
extern int delete_wgate_hash(void);

#endif
