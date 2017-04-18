#ifndef SUBNET_HASH
#define SUBNET_HASH

//0 失败, 1 成功
extern int init_subnet_hash(const char* dbfilename);

extern int update_subnet_hash(void);

//0 不存在, 1 存在
extern char* query_subnet_hash(const char* mac);

extern void delete_subnet_hash(void);

#endif
