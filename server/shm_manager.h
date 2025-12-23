#ifndef SHM_MANAGER_H
#define SHM_MANAGER_H

#include "../common/protocol.h" // Need ItemInfo definition

typedef struct {
    ItemInfo items[MAX_ITEMS_IN_LIST];
    int count;
} SharedData;

// initialize shared memory and semaphore
int shm_init();

// get pointer to shared data
SharedData* shm_get_data();

// lock and unlock for critical section
void shm_lock();
void shm_unlock();

// destroy shared memory and semaphore for graceful shutdown
void shm_destroy();

#endif