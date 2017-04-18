#if 0
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "debug.h"

struct debug_share* debug_shm = NULL;
#ifdef DEBUG_HOOK_TOOL
#ifndef DEBUG
int main(){return 0;}
#else
#include <getopt.h>
//
// usage: me [processName<default:all>] [option<default:exchange>]
// -s show debug info of level all/n
// -a add level all/n
// -d del level all/n
// -e exchange level all/n
// -l show local debug ps
// -p set process 
//

enum operation {
  DEBUG_SHOWLEVEL,
  DEBUG_ADDLEVEL,
  DEBUG_DELLEVEL,
  DEBUG_EXCHANGELEVEL,
  DEBUG_SHOWPS,
  DEBUG_SETPS,
  DEBUG_REMOVE_SHM
};

void usage()
{
  WIPSD_DEBUG("usage: ");
}
void error(const char* errstr)
{
  WIPSD_DEBUG("Error: %s\n", errstr);
  usage();
  debug_shm = NULL;
  exit(0);
}
#define ERROR(s) {WIPSD_DEBUG("Error: %s\n", s);goto exit;}
#define ERROR_(args...) {WIPSD_DEBUG(args);goto exit;}

void parse_numstr(const char* instrconst, char* numstr, int maxnum)
{
  // ", -"
  char* p=NULL;
  int lastNum=-1;
  char* instr=NULL;
  if(instrconst!=NULL){
    instr = (char*)malloc(strlen(instrconst)+1);
  }
  if(instr==NULL)
    error("Optiont string malloc error!");
  strcpy(instr, instrconst);

  p = strtok(instr, ",-");
  while(p!=NULL){
    int curNum=0;
    int i=0;
    while(p[i]!='\0'){
      if(!isdigit(p[i])){
	error("Input opt \"-s -a -d -e\" must be number string delimit by \", -\"!\n");
      }
      i++;
    }
    sscanf(p, "%d", &curNum);
    if(curNum>maxnum)
      error("Input opt number too big!");
    if(instrconst[p-instr-1]=='-'){
      for(i=lastNum;i<=curNum;i++)
	numstr[i] = 's';
    }else{
      numstr[curNum] = 's';
    }
    lastNum = curNum;
    p = strtok(NULL, ",-");
  }
  free(instr);
}

void show_bits()
{
  int j;
  for(j=DEBUG_LEVEL_NUM-1; j>=0;j--)
    WIPSD_DEBUG("%d", (debug_shm->level_onflags&(1<<j))!=0);
  WIPSD_DEBUG("\n");
}

int main(int argc, char* argv[])
{	
	// 1.  еп╤онд╪Ч,  *.key
	int option;
	char showList[DEBUG_LEVEL_NUM];
	char addList[DEBUG_LEVEL_NUM];
	char delList[DEBUG_LEVEL_NUM];
	char exList[DEBUG_LEVEL_NUM];
	enum operation opList[6];
	int opc=0;
	char* psStr=NULL;
	int needshare=0;

	memset(showList, 0, sizeof(showList));
	memset(addList, 0, sizeof(showList));
	memset(delList, 0, sizeof(showList));
	memset(exList, 0, sizeof(showList));
	while ((option = getopt (argc, argv,"s:a:d:e:lp:r")) != EOF){
	  switch(option){
		case 's':
			if(optarg==NULL){
			  memset(showList, 1, sizeof(showList));
			}else{
			  parse_numstr(optarg, showList, DEBUG_LEVEL_NUM);
			}
			opList[opc++] = DEBUG_SHOWLEVEL;
			break;
		case 'a':
			if(optarg==NULL){
			  memset(addList, 1, sizeof(addList));
			}else{
			  parse_numstr(optarg, addList, DEBUG_LEVEL_NUM);
			}
			opList[opc++] = DEBUG_ADDLEVEL;
			needshare++;
			break;
		case 'd':
			if(optarg==NULL){
			  memset(delList, 1, sizeof(delList));
			}else{
			  parse_numstr(optarg, delList, DEBUG_LEVEL_NUM);
			}
			opList[opc++] = DEBUG_DELLEVEL;
			needshare++;
			break;
		case 'e':
			if(optarg==NULL){
			  memset(exList, 1, sizeof(exList));
			}else{
			  parse_numstr(optarg, exList, DEBUG_LEVEL_NUM);
			}
			opList[opc++] = DEBUG_EXCHANGELEVEL;
			needshare++;
			break;
		case 'l':
			opList[opc++] = DEBUG_SHOWPS;
			break;
		case 'r':
			opList[opc++] = DEBUG_REMOVE_SHM;
			needshare++;
			break;
		case 'p':
			psStr = (char*)malloc(strlen(optarg)+7);
			sprintf(psStr, "%s", optarg);
			opList[opc++] = DEBUG_SETPS;
			break;
		default:
			usage();
			exit(0);
			break;
	  }
	}
	
	FILE* mytbl=NULL;
	char fname[150];
	sprintf(fname, "/tmp/%s.tbl", __FILE__);
	if(psStr==NULL){
	  mytbl = fopen(fname, "r");
	  if(mytbl==NULL){
	    ERROR("Don't know which process to debug!");
	  }
	  psStr = malloc(255);
	  memset(psStr, 0, 255);
	  fscanf(mytbl, "%s", psStr);
	  fclose(mytbl);
	  mytbl = NULL;
	}

	FILE* keyfile;
	char kfname[150];
	sprintf(kfname, "/tmp/%s.c.key", psStr);
	if((keyfile=fopen(kfname, "r"))==NULL){
	  ERROR("Process's key not find!");
	}
	int key;
	fscanf(keyfile, "%d", &key);
	fclose(keyfile);
	
	mytbl = fopen(fname, "w+");
	fprintf(mytbl, "%s", psStr);
	fclose(mytbl);
	mytbl = NULL;

	if(needshare){
	  debug_shm = shmat(key, 0, 0);
	  if(debug_shm==(void*)-1){
	    debug_shm = NULL;
	    ERROR("Process key error!");
	  }
	  if(debug_shm->sizeofme!=sizeof(struct debug_share)){
	    ERROR_("Memshare version not support! me:%d, he:%d\n", debug_shm->sizeofme, sizeof(struct debug_share));
	  }
	}

	int i,j;
	for(i=0; i<opc; i++){
	  switch(opList[i]){
	  case DEBUG_SHOWLEVEL:
	    DR(1, 30, "op %d: ShowLevel\t", i);
	    char cmd[256];
	    int countshow=0;
	    sprintf(cmd, "cat /tmp/%s.c.dbg | grep \'%s \\(", psStr, DEBUG_LEVEL_TAGSTR);
	    for(j=0;j<DEBUG_LEVEL_NUM;j++)
	      if(showList[j]!=0){
		sprintf(cmd, "%s%d\\|", cmd, j);
		countshow++;
	      }
	    sprintf(cmd, "%s%s\\)\'", cmd, countshow>1?"\b\b":"");
	    system(cmd);
	    break;
	  case DEBUG_ADDLEVEL:
	    DR(1, 30, "op %d: AddLevel\t", i);
	    for(j=0;j<DEBUG_LEVEL_NUM;j++)
	      if(addList[j]!=0){
		debug_shm->level_onflags |= 1<<j;
		if((debug_shm->level_onflags & (1<<j))==0)
		  ERROR("AddLevel");
	      }
	    show_bits();
	    break;
	  case DEBUG_DELLEVEL:
	    DR(1, 30, "op %d: DelLevel\t", i);
	    for(j=0;j<DEBUG_LEVEL_NUM;j++)
	      if(delList[j]!=0){
		debug_shm->level_onflags &= ~(1<<j);
		if((debug_shm->level_onflags & (1<<j))!=0)
		  ERROR("DelLevel");		
	      }
	    show_bits();
	    break;
	  case DEBUG_EXCHANGELEVEL:
	    DR(1, 30, "op %d: ExchangeLevel\t", i);
	    for(j=0;j<DEBUG_LEVEL_NUM;j++)
	      if(exList[j]!=0){
		unsigned int old_level_onflags = debug_shm->level_onflags;
		debug_shm->level_onflags ^= 1<<j;
		if((debug_shm->level_onflags ^ old_level_onflags)==0)
		  ERROR("ExchangeLevel");
	      }
	    show_bits();
	    break;
	  case DEBUG_SHOWPS:
	    DR(1, 30, "op %d: ShowPs\t%s", i, psStr);
	    WIPSD_DEBUG("%s\n", psStr);
	    break;
	  case DEBUG_SETPS:
	    DR(1, 30, "op %d: SetPs\t%s", i, psStr);
	    break;
	  case DEBUG_REMOVE_SHM:
	    if(debug_shm!=NULL){
		int key = debug_shm->key;
		shmdt(debug_shm);
		shmctl(key, IPC_RMID, NULL);
		debug_shm = NULL;
	    }
	    break;
	  }
	  DR(1, 30, "\n");
	}

 exit:		
	if(debug_shm!=NULL){
	  shmdt(debug_shm);
	  debug_shm = NULL;
	}
	free(psStr);
	return 0;
}

#endif
#endif
#endif
