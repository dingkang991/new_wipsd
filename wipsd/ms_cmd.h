/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *  Copyright (C) 2011 Secriver Scientific Inc Co., Ltd * * * *
 *  autor:Yan Quan Cheng <yanquancheng@secriver.cn>  * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#ifndef __MS_CMD_H__
#define __MS_CMD_H__

//#include <stdlib.h>
#define CMD_NAME_SIZE 32
enum cmd_id{
	W_DEV_REGISTER =0,
	W_DEV_KEEPLIVE,
	M_SERVER_SEND_CONFIG,
	M_SERVER_SEND_POLICY,
	M_SERVER_SEND_SOFT_V,
	M_SERVER_SEND_W_DEV_INFO,

	M_SERVER_SEND_BLOCK_CMD,
	M_SERVER_SEND_DEBLOCK_CMD,

	M_SERVER_GET_WLIST,
	M_SERVER_GET_STATLIST,
	M_SERVER_GET_BLKLIST,

	M_SERVER_GET_EVENT_LOG,
	M_SERVER_GET_NORMAL_LOG,

};

struct ms_cmd{
	int cmd_id;
	char name[CMD_NAME_SIZE];
	int cmd_type;
	char *data;


};

struct cmd_req_head
{
	int pro_version;
	int data_len;
	enum cmd_id id;
	int seq_num;
};

struct cmd_resp_head
{
	int pro_version;
	int data_len;
	enum cmd_id id;
	int seq_num;
	int success_flag; //0-ok 1-false
};
#endif
