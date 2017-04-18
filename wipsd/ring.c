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
#include "ring.h"
#include "debug.h"
#if 0
struct ring_control* new_ring(int size, int nodesize)
{
	void* memclean[3];
	int mem_c=0;
#define PUSH_ALLOC(address) (memclean[mem_c++]=(address))
#define POP_ALLOC() (memclean[mem_c--])
#define WMALLOC(var, size) { \
	if(PUSH_ALLOC(var=malloc(size))==NULL) goto exit_fail; \
}
	struct ring_control* ring;

	WMALLOC(ring, sizeof(*ring));
	WMALLOC(ring->pentry, size*sizeof(struct ring_entry));
	WMALLOC(ring->pdata, size*nodesize);
  
	if(sem_init(&ring->enable_num, 0, size)!=0) goto exit_fail;
	if(sem_init(&ring->deable_num, 0, 0)!=0) goto exit_sem_fail;
	ring->capacity = size;
	ring->nodesize = nodesize;
	ring->head = (struct ring_entry*)ring->pentry;
	ring->headind = 0;
	ring->tail = (struct ring_entry*)ring->pentry + size - 1;
	ring->tailind = size-1;
	ring->nodenum = 0;
	int i;
	for(i=0;i<size;i++){
		((struct ring_entry*)ring->pentry+i)->data = ring->pdata + i*nodesize;
		((struct ring_entry*)ring->pentry+i)->next = (struct ring_entry*)ring->pentry+i+1;
	}
	((struct ring_entry*)ring->pentry+size-1)->next = (struct ring_entry*)ring->pentry;
	return ring;
exit_sem_fail:
	sem_destroy(&ring->enable_num);
exit_fail:
	while(mem_c>=0) free(POP_ALLOC());
	return NULL;
}
#endif
int enqueue_ring(struct ring_control* ring, const void* node)
{
	//若出错，让 nodenum 和 ring 恢复到调用前
	if( ring==NULL || node==NULL ) return 0;
	if(sem_trywait(&ring->enable_num)!=0) return 0;
	ring->tail = ring->tail->next;
	memcpy(ring->tail->data, node, ring->nodesize);
	ring->nodenum++;
	++ring->tailind;
	if(ring->tailind > ring->capacity-1){
	  ring->tailind %= ring->capacity;
	}
	sem_post(&ring->deable_num);
	return 1;
}

int dequeue_ring(struct ring_control* ring, void** node)
{
	//若出错，让 nodenum 和 ring 恢复到调用前
	if( ring==NULL || ring->nodenum<=0)   return 0;
	if(sem_trywait(&ring->deable_num)!=0) return 0;
	if( node!=NULL ){
		*node = ring->head->data;
	}
	ring->nodenum--;
	ring->head = ring->head->next;
	++ring->headind;
	if(ring->headind > ring->capacity-1){
	  ring->headind %= ring->capacity;
	}
	sem_post(&ring->enable_num);
	return 1;  
}

int traverse_ring(struct ring_control* ring, int ringfd, void** pnode)
{
	// return Next 
	if( ring !=NULL &&  pnode!=NULL ){
		if( ringfd < 0 ){
		  *pnode = NULL;
		  return ring->headind;
		}else{
			if( ring->headind <= ring->tailind ){
				if( ringfd>=ring->headind && ringfd<=ring->tailind ){
					*pnode = ring->pdata + ring->nodesize*ringfd;
				}else{
					ringfd = ring->headind;
					*pnode = NULL;
				}
			}else{
				if( ringfd>=ring->headind || ringfd<=ring->tailind ){
				*pnode = ring->pdata + ring->nodesize*ringfd;
				}else{
				ringfd = ring->headind;
				*pnode = NULL;
				}      
			}
		  
		  	return (ringfd+1)%ring->capacity;
		}
	}
	return -1;
}
#if 0
void delete_ring(struct ring_control* ring)
{
	sem_destroy(&ring->enable_num);
	sem_destroy(&ring->deable_num);
	wipsd_free(ring->pdata);
	wipsd_free(ring->pentry);
	wipsd_free(ring);
}
#endif
sig_atomic_t getlength_ring(struct ring_control* ring)
{
	return ring==NULL?0:ring->nodenum;
}

int is_ring_empty(struct ring_control* ring)
{
	if(sem_trywait(&ring->deable_num) != 0){
		return 1;
	}
	sem_post(&ring->deable_num);
	return 0;
}

int is_ring_full(struct ring_control* ring)
{
	if(sem_trywait(&ring->enable_num) != 0){
		return 1;
	}
	sem_post(&ring->enable_num);
	return 0;
}

int isflowover_ring(struct ring_control* ring)
{
	return ring==NULL?0:(ring->nodenum>ring->capacity);
}

int snapshot_ring(struct ring_control* ring, sig_atomic_t* head, sig_atomic_t* tail)
{
	if( ring!=NULL && ring->nodenum>0 ){
		if( head!=NULL ){
			*head = ring->headind;
		}
		if( tail!=NULL ){
			*tail = ring->tailind;
		}
		return 1;
	}
	return 0;
}

int getnodes_ring(struct ring_control* ring, sig_atomic_t startind, sig_atomic_t endind, void* buffer)
{
	if( ring==NULL || buffer==NULL ) 
		return 0;

#define MOD(boundv, bound) boundv %= bound;boundv+=boundv<0?bound:0
MOD(startind, ring->capacity);
MOD(endind, ring->capacity);
	if( startind <= endind ){
		memcpy(buffer, ring->pdata+ring->nodesize*startind, ring->nodesize*(endind-startind+1));
		return endind-startind+1;
	}else{
		memcpy(buffer, ring->pdata+ring->nodesize*startind, ring->nodesize*(ring->capacity-startind));
		memcpy(buffer+ring->nodesize*(ring->capacity-startind), ring->pdata, ring->nodesize*(endind+1));
		return endind-startind+1+ring->capacity;
	}
}
