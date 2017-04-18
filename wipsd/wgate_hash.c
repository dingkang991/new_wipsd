#include <zebra.h>
#include "zthread_support.h"
#include "if_support.h"
#include "fs_support.h"
#include "io_support.h"
#include "getopt.h"
#include "daemon.h"
#include "mac.h"
#include "zclient.h"
#include "vty.h"
#include "../vtysh/vtysh.h"
#include <linux/if.h>
#include <linux/un.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include <linux/in.h>
#include "obstack.h"
#include "hash.h"
#include "ieee80211.h"
#include "sqlite3.h"

#include "wipsd_wnode.h"
#include "obstack.h"
#include "hash.h"
#include "wgate_hash.h"

#define TRY_TIMES_OPEN_DBFILE 10
struct hash_control* __wgate_hash_table__=NULL;
char* __wgate_dbfilename__=NULL;

struct ip_list {
  unsigned char ip[6];
  struct ip_list* next;
};

#define DEBUG_WGATE_HASH
#ifdef DEBUG_WGATE_HASH
#define DEBUG_PRINT(formatstr, instr, outstr) {\
    WIPSD_DEBUG(formatstr==NULL?"CALL %s-----IN \"%s\", OUT \"%s\"\n":formatstr, __FUNCTION__, instr==NULL?"NULL":instr, outstr==NULL?"NULL":outstr);	\
}
#else
#define DEBUG_PRINT(formatstr, instr, outstr)
#endif


#define DB_ERROR_PRINT(db)  WIPSD_DEBUG("\nSQLITE3 ERROR:%s, In file %s, line %d\n\n", sqlite3_errmsg(db), __FILE__, __LINE__);
#define DB_WARNING_PRINT(db, str)  WIPSD_DEBUG("\nSQLITE3 WARNING:%s, In file %s, line %d\t%s\n\n", sqlite3_errmsg(db), __FILE__, __LINE__, str);

static void destroy (char *string, char *value)
{
	struct ip_list* iplist = (struct ip_list *)value;

	wipsd_free (string);
	while(iplist!=NULL){
		void* tofree;
		tofree = iplist;
		iplist = iplist->next;
		wipsd_free (tofree);
	}
}

static void delete_wgate_hash_table(struct hash_control* hashtable)
{
	hash_traverse(hashtable, (void(*)(const char*, void*))destroy);
	hash_die(hashtable);
}


static int close_dbfile(sqlite3* db, sqlite3_stmt* stmt)
{
	if(stmt!=NULL){
		sqlite3_finalize(stmt);
	}
	if(db!=NULL){
		sqlite3_close(db);
	}
	return 1;
}
/*
static int rowcount=0;
int read_wgate_hash(void* data, int n_columns, char** column_values, char** column_names)
{
  struct hash_control* htable = data;  
  char* macstr = column_values[7];
  char* ipstr = column_values[6];
  unsigned char* mac;
  unsigned char* ip;
		if(mac==NULL || ip==NULL){
		  WIPSD_DEBUG("mac %s, ip %s\n", macstr==NULL ? "NULL" : macstr, ipstr==NULL ? "NULL" : "ipstr");
		  delete_wgate_hash_table(htable);
		  htable=NULL;
		  break;
		}else if(strcmp(ipstr, "")!=0 && strcmp(macstr, "")!=0 ){
			mac	=	malloc(12);
			ip	=	malloc(8);
			sscanf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", mac+0, mac+1, mac+2, mac+3, mac+4, mac+5);
			sscanf(ipstr, "%d.%d.%d.%d", ip+0, ip+1, ip+2, ip+3);
			hash_insert(htable, mac, 6, (void*) ip);
			WIPSD_DEBUG("wgate insert %02x:%02x:%02x:%02x:%02x:%02x\t%d.%d.%d.%d\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],ip[0],ip[1],ip[2],ip[3] );
		}else{
  		  WIPSD_DEBUG("error string, mac %s ip %s\n", macstr, ipstr);
		}

}*/

static struct hash_control* create_wgate_hash_table(sqlite3* db,   sqlite3_stmt* stmt)
{
	struct hash_control* htable = hash_new();
	while(sqlite3_step(stmt)==SQLITE_ROW){
		char* macstr = (char*)sqlite3_column_text(stmt, 0);
		char* ipstr = (char*)sqlite3_column_text(stmt, 1) ;
		unsigned char mac[12];
		unsigned char ip[8];
		if(macstr==NULL || ipstr==NULL){
		  WIPSD_DEBUG("mac %s, ip %s\n", macstr==NULL ? "NULL" : macstr, ipstr==NULL ? "NULL" : "ipstr");
		  delete_wgate_hash_table(htable);
		  htable=NULL;
		  break;
		}else if(strcmp(ipstr, "")!=0 && strcmp(macstr, "")!=0 && strcmp(ipstr, "Unknown")!=0 && strcmp(macstr, "Unknown")!=0){
		  struct ip_list* iplist;
			sscanf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x", mac+0, mac+1, mac+2, mac+3, mac+4, mac+5);
			sscanf(ipstr, "%d.%d.%d.%d/%d", ip+0, ip+1, ip+2, ip+3, ip+4);
			iplist = hash_find(htable, (char *)mac, 6);
			if(iplist==NULL){
			  unsigned char* kmac;
			  kmac = malloc(6);
			  memcpy(kmac, mac, 6);
			  iplist = malloc(sizeof(*iplist));
			  iplist->next = NULL;
			  memcpy(iplist->ip, ip, 6);
			  hash_insert(htable, (char *)kmac, 6, (void*) iplist);
			}else{
			  while(iplist->next!=NULL){
			    if(memcmp(iplist->ip, ip, 5)==0){
			      break;
			    }
			    iplist = iplist->next;
			  }
			  if(memcmp(iplist->ip, ip, 5)!=0 && iplist->next==NULL){
			    struct ip_list* newnode;
			    newnode = malloc(sizeof(*newnode));
			    newnode->next = NULL;
			    memcpy(newnode->ip, ip, 5);
			    iplist->next = newnode;
			  }
			}
			//WIPSD_DEBUG("wgate insert %02x:%02x:%02x:%02x:%02x:%02x\t%d.%d.%d.%d/%d\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],ip[0],ip[1],ip[2],ip[3], ip[4] );
		}else{
  		  WIPSD_DEBUG("error string, mac %s ip %s\n", macstr, ipstr);
		}
	}
	/*	rowcount=0;
	if(sqlite3_exec(sql, "select * from wnet", read_wgate_hash, htable,NULL)!=SQLITE3_OK || rowcount==0){
	  delete_wgate_hash_table(htable);
	  htable=NULL;
	  }*/
	return htable;
}

static int open_dbfile(const char* dbfilename, sqlite3** db, sqlite3_stmt** stmt)
{
	int i;
	for(i=0;i<TRY_TIMES_OPEN_DBFILE;i++){
		if(   sqlite3_open(dbfilename, db)==SQLITE_OK ) {
			if( sqlite3_prepare(*db, "select mac,ip from wnet", -1, stmt, 0)==SQLITE_OK ){
				goto open_db_exit_success;
			}else{
				if(i<TRY_TIMES_OPEN_DBFILE-1) {
					if(*stmt!=NULL) {
						sqlite3_finalize(*stmt);
					}
					sqlite3_close(*db);
				}
			}
		}else{
			if(i<TRY_TIMES_OPEN_DBFILE-1) sqlite3_close(*db);
		}
	}
	// open_db_exit_fail:
	*stmt = NULL;
	return 0;

open_db_exit_success:
	return 1;
}

int init_wgate_hash(const char* dbfilename)
{
	int filenamelen = strlen(dbfilename)+1;
	__wgate_dbfilename__ = (char*)malloc(filenamelen);
	strncpy(__wgate_dbfilename__, dbfilename, filenamelen>256?256:filenamelen);
	sqlite3* db=NULL;
	sqlite3_stmt* stmt=NULL;
	if(open_dbfile(dbfilename, &db, &stmt)==0) goto init_exit_fail;

	__wgate_hash_table__=create_wgate_hash_table(db, stmt);
	close_dbfile(db, stmt);
	if(__wgate_hash_table__==NULL) {
		goto init_exit_fail;
	}

	// init_exit_success:
	return 0;
init_exit_fail:
	return -1;
}
#if 0
int update_wgate_hash(void)	/**/
{
	sqlite3* db=NULL;
	sqlite3_stmt* stmt=NULL;
//	struct hash_control* bhash=NULL;	
	if(__wgate_hash_table__==NULL || __wgate_dbfilename__==NULL){
		return 0;
	}
	if(open_dbfile(__wgate_dbfilename__, &db, &stmt)==0) goto update_exit_warning;
	delete_wgate_hash_table(__wgate_hash_table__);
	__wgate_hash_table__ = create_wgate_hash_table(db, stmt);
	close_dbfile(db, stmt);
	
	if(__wgate_hash_table__==NULL) {
	  goto update_exit_fail;
	}

	// update_exit_success:
	//DEBUG_PRINT(NULL, NULL, "success");
	return 1;
update_exit_warning:
	//DB_WARNING_PRINT(db, "UPDATE FAIL, USE LAST WGATE_HASH_TABLE!");
	close_dbfile(db, stmt);
	return 1;
update_exit_fail:
	//DEBUG_PRINT(NULL, NULL, "fail");
	return 0;
}
#endif
const unsigned char* query_wgate_hash(const unsigned char* mac)
{
  if(__wgate_hash_table__==NULL){
    return NULL;
  }
  return hash_find(__wgate_hash_table__, (char *)mac, 6);
}

static int is_same_subnet(__u8* gateip, __u8* staip,__u8 mask)
{
  __u8 bmask[4];
  int i=mask;
  unsigned long lmask=0x80000000;
  memset(bmask, 0, sizeof(bmask));
  while(mask>=2){
    lmask |= lmask>>1;
    mask--;
  }
  if(i>0){
    bmask[0] = (lmask>>24)&0xff;
    bmask[1] = (lmask>>16)&0xff;
    bmask[2] = (lmask>>8)&0xff;
    bmask[3] = (lmask)&0xff;
  }

#define MASK_EQ(bit) ((bmask[bit]&staip[bit])==(bmask[bit]&gateip[bit]))
  return MASK_EQ(0)&&MASK_EQ(1)&&MASK_EQ(2)&&MASK_EQ(3);
}

unsigned char* query_wgate_hash_with_ip(unsigned char *mac, unsigned char* ip)
{
  struct ip_list* iplist;
  if(__wgate_hash_table__==NULL){
    return NULL;
  }
  iplist = hash_find(__wgate_hash_table__, (char *)mac, 6);
  while(iplist!=NULL){
    if(is_same_subnet(iplist->ip, ip, iplist->ip[4])){
      return iplist->ip;
    }
    iplist = iplist->next;
  }
  return NULL;
}

int is_wgate_hash_null(void)
{
  return __wgate_hash_table__==NULL;
}
#if 0
int delete_wgate_hash(void)
{
	if(__wgate_hash_table__!=NULL){
		delete_wgate_hash_table(__wgate_hash_table__);
		__wgate_hash_table__ = NULL;
	}
	if(__wgate_dbfilename__!=NULL){  
		wipsd_free(__wgate_dbfilename__);
		__wgate_dbfilename__ = NULL;
	}

	return 0;
}
#endif
