#ifndef HLS_CONFIG_UTIL_H
#define	HLS_CONFIG_UTIL_H

#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "sys/hls_config.h"



#ifndef OBJ_SIZE_MAX
#define	OBJ_SIZE_MAX		5120			// hls_head + datalen
#endif

struct cfg_req *alloc_req(int extra);
int do_hls_config(__u32 objtype, __u32 cmdtype, __u32 ID, char *name, __u32 refer, __u32 refer_block[MAX_REFER_NUM], __u32 datalen, void *data);
int get_num_by_type(__u32 type);
int get_obj_by_ID(__u32 type, __u32 ID, char **buf, int *len);
int get_obj_by_name(__u32 type, char *name, char **buf, int *len);
int get_obj_by_type(__u32 type, char **buf, int *len);
__u32 get_type_by_ID(__u32 ID);
__u32 get_type_by_name(char *name);
char *get_name_by_ID(__u32 ID);
__u32 get_ID_by_name(char *name, __u32 *type);
int delete_obj_by_ID(__u32 type, __u32 ID);
int delete_obj_by_name(__u32 type, char *name);
int delete_obj_by_type(__u32 type);
int add_obj(__u32 objtype, char *name, __u32 refer, __u32 refer_block[MAX_REFER_NUM], __u32 datalen, void *data);
int modify_obj(__u32 objtype, __u32 ID, char *name, __u32 refer, __u32 refer_block[MAX_REFER_NUM], __u32 datalen, void *data);
int rename_obj_by_name(__u32 objtype, char *oldname, char *newname);
int move_obj_vs(__u32 objtype, __u32 ID, __u32 ID2, int dir);

#define DATA2OBJ(x) ((struct hls_obj_head *)((unsigned long)x - sizeof(struct hls_obj_head)))

#define for_each_obj(pos, obj, buf, len) \
	for (pos = (typeof(pos))((unsigned long)buf + sizeof(struct hls_obj_head)), obj = (struct hls_obj_head *)buf; \
		buf && (unsigned long)pos + OBJ_DATA_ALIGN((DATA2OBJ(pos))->data_len) <= (unsigned long)buf + len; \
		pos = (typeof(pos))((unsigned long)pos + OBJ_DATA_ALIGN(DATA2OBJ(pos)->data_len + sizeof(struct hls_obj_head))),\
		obj = DATA2OBJ(pos))


struct cfg_buf {
	char *buf;
	unsigned int offset;
	unsigned int len;
};

static inline int cfg_buf_init(struct cfg_buf *buf)
{
	buf->buf = calloc(1, 8192);
	if (!buf->buf)
		return -1;
	
	buf->offset = 0;
	buf->len = 8191;

	return 0;
}

static inline void cfg_buf_free(struct cfg_buf *buf)
{
	free(buf->buf);
}

#endif


