#ifndef RING_H
#define RING_H

#include <signal.h>
#include <semaphore.h>

struct ring_entry {
	struct ring_entry* next;
	void* data;
};

struct ring_control {
	struct ring_entry* head; // TYPE: read then move
	struct ring_entry* tail; // TYPE: move then write
	void* pentry; 
	void* pdata; 
	int capacity; // 环节点总数
	int nodesize; // 单个node的字节数
	sem_t enable_num;
	sem_t deable_num;
	sig_atomic_t nodenum;
	sig_atomic_t headind;
	sig_atomic_t tailind;
};

extern struct ring_control* new_ring(int size, int nodesize);
extern void delete_ring(struct ring_control* ring);

// 0: fail, 1:success
extern int enqueue_ring(struct ring_control* ring, const void* node);
extern int dequeue_ring(struct ring_control* ring, void** node);
extern int is_ring_empty(struct ring_control* ring);
extern int is_ring_full(struct ring_control* ring);
extern int traverse_ring(struct ring_control* ring, int ringfd, void** buffer);
extern int snapshot_ring(struct ring_control* ring, sig_atomic_t* head, sig_atomic_t* tail);
extern int getnodes_ring(struct ring_control* ring, sig_atomic_t startind, sig_atomic_t endind, void* buffer);

extern  sig_atomic_t getlength_ring(struct ring_control* ring);

// 0:not, 1:flowover
extern int isflowover_ring(struct ring_control* ring);



#endif
