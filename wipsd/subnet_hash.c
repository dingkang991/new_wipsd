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

#include "subnet_hash.h"

#define TRY_TIMES_OPEN_DBFILE 10
struct hash_control* __subnet_hash_table__=NULL;
char* __subnet_dbfilename__=NULL;

//#define DEBUG_SUBNET_HASH
#ifdef DEBUG_SUBNET_HASH
#define DEBUG_PRINT(formatstr, instr, outstr) {\
    WIPSD_DEBUG(formatstr==NULL?"CALL %s-----IN \"%s\", OUT \"%s\"\n":formatstr, __FUNCTION__, instr==NULL?"NULL":instr, outstr==NULL?"NULL":outstr);	\
}
#else
#define DEBUG_PRINT(formatstr, instr, outstr)
#endif


#define DB_ERROR_PRINT(db)  WIPSD_DEBUG("\nSQLITE3 ERROR:%s, In file %s, line %d\n\n", sqlite3_errmsg(db), __FILE__, __LINE__);
#define DB_WARNING_PRINT(db, str)  WIPSD_DEBUG("\nSQLITE3 WARNING:%s, In file %s, line %d\t%s\n\n", sqlite3_errmsg(db), __FILE__, __LINE__, str);

static const char* mac_tolower(const char* mac)
{
  static char maclower[20];
  int i=0;
  for(;i<sizeof(maclower) && *mac!=0;i++,mac++){
    maclower[i] = tolower(*mac);
  }
  maclower[i] = '\0';
  return maclower;
}

static char* xstrdup (const char *string)
{
  return strcpy (malloc (strlen (string) + 1), string);
}

static void destroy (char *string, char *value)
{
  wipsd_free (string);
  wipsd_free (value);
}

static void delete_subnet_hash_table(struct hash_control* hashtable)
{
  hash_traverse(hashtable, (void(*)(const char*, void*))destroy);
  hash_die(hashtable);
}

static int open_dbfile(const char* dbfilename, sqlite3** db, sqlite3_stmt** stmt)
{
  int i;
  for(i=0;i<TRY_TIMES_OPEN_DBFILE;i++){
    if(   sqlite3_open(dbfilename, db)==SQLITE_OK ) {
      if( sqlite3_prepare(*db, "select mac,name from subnet", -1, stmt, 0)==SQLITE_OK ){
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

static struct hash_control* create_subnet_hash_table(sqlite3* db,   sqlite3_stmt* stmt)
{
  struct hash_control* htable = hash_new();
  while(sqlite3_step(stmt)==SQLITE_ROW){
    const char* mac = xstrdup( mac_tolower((char*)sqlite3_column_text(stmt, 0)) );
    char* subnet = xstrdup( (char*)sqlite3_column_text(stmt, 1) );
    hash_insert(htable, mac, strlen(mac)+1, (void*) subnet);
    if(mac==NULL || subnet==NULL){
      delete_subnet_hash_table(htable);
      htable=NULL;
      break;
    }
  }
  return htable;
}

static char* query_subnet_macexist(struct hash_control* hashtable, const char* mac)
{
  return hash_find(hashtable, mac, strlen(mac)+1);
}

int init_subnet_hash(const char* dbfilename)
{
  int filenamelen = strlen(dbfilename)+1;
  __subnet_dbfilename__ = (char*)malloc(filenamelen);
  strncpy(__subnet_dbfilename__, dbfilename, filenamelen>256?256:filenamelen);
  sqlite3* db=NULL;
  sqlite3_stmt* stmt=NULL;
  if(open_dbfile(dbfilename, &db, &stmt)==0) goto init_exit_fail;

  __subnet_hash_table__=create_subnet_hash_table(db, stmt);
  close_dbfile(db, stmt);
  if(__subnet_hash_table__==NULL) {
    goto init_exit_fail;
  }

	// init_exit_success:
	return 0;
	init_exit_fail:
	return -1;
}

int update_subnet_hash(void)
{
  if(__subnet_hash_table__==NULL || __subnet_dbfilename__==NULL){
    return 0;
  }
  sqlite3* db=NULL;
  sqlite3_stmt* stmt=NULL;
  if(open_dbfile(__subnet_dbfilename__, &db, &stmt)==0) goto update_exit_warning;
  delete_subnet_hash_table(__subnet_hash_table__);
  __subnet_hash_table__ = create_subnet_hash_table(db, stmt);
  close_dbfile(db, stmt);
  if(__subnet_hash_table__==NULL) goto update_exit_fail;

// update_exit_success:
  DEBUG_PRINT(NULL, NULL, "success");
  return 1;
 update_exit_warning:
  DB_WARNING_PRINT(db, "UPDATE FAIL, USE LAST SUB_NET_HASH_TABLE!");
  close_dbfile(db, stmt);
  return 1;
 update_exit_fail:
  DEBUG_PRINT(NULL, NULL, "fail");
  return 0;
}

char* query_subnet_hash(const char* mac)
{
  if(__subnet_hash_table__==NULL || __subnet_dbfilename__==NULL || mac==NULL){
    DEBUG_PRINT(NULL, mac, NULL);
    return NULL;
  }
  DEBUG_PRINT(NULL, mac, query_subnet_macexist(__subnet_hash_table__, mac_tolower(mac)));
  return query_subnet_macexist(__subnet_hash_table__, mac_tolower(mac));
}
#if 0
void delete_subnet_hash(void)
{
  if(__subnet_hash_table__!=NULL){
    delete_subnet_hash_table(__subnet_hash_table__);
    __subnet_hash_table__ = NULL;
  }
  if(__subnet_dbfilename__!=NULL){  
    wipsd_free(__subnet_dbfilename__);
    __subnet_dbfilename__ = NULL;
  }
}
#endif
#if 0
int main(int argn, char* argv[])
{
  init_subnet_hash("wconfig.db");
  update_subnet_hash();
  query_subnet_hash("ff:Ff:ff:ff:ff:ff");
  update_subnet_hash();
  delete_subnet_hash();
  char op;
  char filename[256];
  char mac[100];
  int retcode=-1;
  char* net;
  int delaytime=0;
  int loop=1;
  int inited=0;
  while(loop){
    scanf("%c", &op);
    switch(op){
    case 'i':case 'I':
      scanf("%s", &filename[0]);
      retcode = init_subnet_hash(filename);
      if(retcode>0) inited=1;
      WIPSD_DEBUG("CALL:\tinit_subnet_hash( %s )\t\t\t\tret %d \n", filename, retcode);
      break;
    case 'u':case 'U':
      scanf("%d", &delaytime);
      if(inited==1){
	retcode = update_subnet_hash();
	WIPSD_DEBUG("CALL:\tupdate_subnet_hash()\t\t\t\t\tret %d, delaytime %d\n", retcode, delaytime);
      }else{
      	WIPSD_DEBUG("NOT INITIALIZE! BEFORE CALL update_sunet_hash()\n");
      }
      if(retcode==0) inited=0;
      break;
    case 'q':case 'Q':
      scanf("%s", &mac[0]);
      if(inited==1){
        net = query_subnet_hash(mac);
	WIPSD_DEBUG("CALL:\tquery_subnet_hash( %s )\t\t\tret %s \n", mac, net==NULL?"NULL":net);
      }else{
	WIPSD_DEBUG("NOT INITIALIZE! BEFORE CALL query_sunet_hash()\n");
      }
      break;
    case 'd':case 'D':
      delete_subnet_hash();
      inited=0;
      WIPSD_DEBUG("CALL:\tdelete_subnet_hash()\n");
      break;
    case 'e':
      loop = 0;
      break;
    }
  }

  return 0;
}
#endif
